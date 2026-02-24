# Automotive Pentesting Testbed - Objectives

This document describes the twelve security challenges (V1-V12) available in the testbed. Your goal is to discover and exploit each vulnerability to prove successful compromise.

**Note**: Vulnerabilities V9-V12 require **fuzzing techniques** to discover. These challenges are designed to be discovered through automated testing tools rather than manual inspection.

## Challenge Matrix

| ID | Name | Category | Difficulty | Port/Target |
|----|------|----------|------------|-------------|
| V1 | SSH Access | Network Security | Easy | Port 22 |
| V2 | SQL Injection | Web Application | Easy | Port 8000 |
| V3 | CAN Door Control | Vehicle Network | Easy | vcan0 |
| V4 | CAN Replay | Vehicle Network | Easy | vcan0 |
| V5 | Directory Traversal | Web Application | Medium-Hard | Port 8080 |
| V6 | Command Injection | Web Application | Medium | Port 8000 |
| V7 | IDOR | Web Application | Medium | Port 8000 |
| V8 | Buffer Overflow | Binary Exploitation | Hard | Port 9555 |
| V9 | UDS Security Bypass | Protocol Fuzzing | Hard | Port 9556 / vcan0 |
| V10 | CAN DLC Overflow | Protocol Fuzzing | Hard | vcan0 |
| V11 | UDS Integer Overflow | Protocol Fuzzing | Hard | Port 9556 / vcan0 |
| V12 | Firmware Header Overflow | Protocol Fuzzing | Hard | Port 9556 / vcan0 |

## Overview

The testbed simulates a vulnerable automotive system with the following attack surfaces:
- **Network Services**: SSH, web interfaces, OBD-II service, and UDS Gateway
- **CAN Bus**: Virtual CAN interface (vcan0) for vehicle communication
- **Gateway Service**: Firmware management interface
- **OBD-II Service**: Vehicle diagnostics interface (C binary)
- **UDS Gateway**: Unified Diagnostic Services protocol implementation (TCP + CAN)
- **CAN Frame Parser**: CAN frame analysis service

Use the Validation API at `http://localhost:9999` to verify exploit success.

---

## V1: SSH Access

**Category**: Network Security
**Target**: SSH Server (port 22)
**Validation Endpoint**: `GET /validate/ssh_access`

### Description

The vehicle gateway exposes an SSH service for maintenance access. The system administrator may have left default credentials in place.

### Objective

Gain shell access to the system via SSH.

### Hints

- Default credentials are a common security issue in embedded systems
- The username is often something predictable like "admin" or "root"
- Password complexity requirements may not be enforced

### Success Criteria

The validation API will return `success: true` when you have an active SSH session as the target user.

---

## V2: SQL Injection

**Category**: Web Application Security
**Target**: Infotainment Web Interface (port 8000)
**Validation Endpoint**: `GET /validate/sqli_success`

### Description

The infotainment system provides a web-based login portal. The authentication mechanism may be vulnerable to injection attacks.

### Objective

Bypass the login authentication without knowing valid credentials.

### Hints

- Test the login form with various special characters
- SQL injection often exploits string concatenation in queries
- The classic payload structure: manipulate the WHERE clause logic

### Success Criteria

The validation API will return `success: true` when authentication bypass is detected.

---

## V3: CAN Bus Door Control

**Category**: Vehicle Network Security
**Target**: Virtual CAN Bus (vcan0)
**Validation Endpoint**: `GET /validate/doors_unlocked`

### Description

The vehicle's door lock system is controlled via CAN bus messages. Without proper authentication, an attacker with CAN bus access could unlock the doors.

### Objective

Send CAN messages to unlock all four doors (front-left, front-right, rear-left, rear-right).

### CAN Message Format

Door control messages use the following format:

| Field | Value |
|-------|-------|
| CAN ID | `0x19B` |
| Data Length | 8 bytes |

**Door State Data (bytes 4-7)**:
- Byte 4: Front Left door
- Byte 5: Front Right door
- Byte 6: Rear Left door
- Byte 7: Rear Right door

**Values**:
- `0x00` = Locked
- `0xFF` = Unlocked (any non-zero value)

### Example Commands

Using `cansend` from can-utils:

```bash
# Unlock all doors
cansend vcan0 19B#00000000FFFFFFFF

# Lock all doors
cansend vcan0 19B#0000000000000000
```

### Success Criteria

The validation API will return `success: true` when all four doors report unlocked state.

---

## V4: CAN Replay Attack

**Category**: Vehicle Network Security
**Target**: Virtual CAN Bus (vcan0)
**Validation Endpoint**: `GET /validate/can_replay`

### Description

CAN bus traffic may contain sensitive commands that can be captured and replayed. If the system doesn't validate message freshness, replay attacks become possible.

### Objective

Capture and replay CAN bus traffic to trigger the replay detection mechanism.

### Hints

- Use `candump` to capture CAN traffic
- Use `canplayer` to replay captured traffic
- The system detects replay attacks by monitoring for rapid bursts of identical door frames (5+ identical frames on CAN ID 0x19B within 2 seconds)
- Both `canplayer` replay and rapid `cansend` loops will trigger detection

### Success Criteria

The validation API will return `success: true` when a replay attack pattern is detected (rapid identical door frames).

---

## V5: Directory Traversal

**Category**: Web Application Security
**Difficulty**: Medium-Hard
**Target**: Gateway Service (port 8080)
**Validation Endpoint**: `GET /validate/directory_traversal`

### Description

The gateway service provides a firmware upload interface for system updates. The file handling mechanism may not properly sanitize filenames, allowing an attacker to read arbitrary files from the system.

**Note**: This endpoint has a WAF-like input filter that blocks simple traversal attempts. You must bypass the filter.

### Objective

Exploit the firmware upload endpoint to read sensitive files outside the intended upload directory.

### Hints

- Firmware upload endpoints often use the uploaded filename directly
- Simple path traversal sequences like `../` are blocked by an input filter
- WAF bypass techniques exist: encoding, nested sequences, or mixed patterns
- Consider URL encoding and double encoding
- The goal is to read system files, not write malicious content
- Consider what sensitive files exist on Linux systems (e.g., `/etc/passwd`)
- The endpoint accepts multipart file uploads

### Success Criteria

The validation API will return `success: true` when a successful directory traversal (with WAF bypass) is detected.

---

## V6: Command Injection

**Category**: Web Application Security
**Difficulty**: Medium
**Target**: Infotainment Web Interface (port 8000)
**Validation Endpoint**: `GET /validate/command_injection`

### Description

The infotainment system allows media file uploads that are processed by the server. The file processing mechanism may pass user-controlled data to system commands without proper sanitization.

### Objective

Exploit the media upload functionality to execute arbitrary operating system commands.

### Hints

- Media processing often involves command-line tools (e.g., ffmpeg)
- Filenames may be passed to shell commands
- Shell metacharacters can break out of intended command context
- Common injection characters: `;`, `|`, `&`, `$()`, backticks
- The command output may be visible in the response or logs

### Success Criteria

The validation API will return `success: true` when command injection is detected.

---

## V7: Insecure Direct Object Reference (IDOR)

**Category**: Web Application Security
**Difficulty**: Medium
**Target**: Infotainment Web Interface (port 8000)
**Validation Endpoint**: `GET /validate/idor`

### Description

The infotainment system has a settings page where users can view and modify their profile information. The access control mechanism may not properly verify that users can only access their own data.

### Objective

Access another user's settings data by manipulating request parameters.

### Hints

- Look for numeric identifiers in URLs or query parameters
- User IDs are often sequential integers
- The system has multiple user accounts (admin, driver, owner)
- Try accessing resources that belong to other users
- Authentication doesn't always mean authorization

### Success Criteria

The validation API will return `success: true` when unauthorized access to another user's data is detected.

---

## V8: Buffer Overflow (Advanced)

**Category**: Binary Exploitation
**Difficulty**: Hard
**Target**: OBD-II Service (port 9555)
**Validation Endpoint**: `GET /validate/buffer_overflow`

### Description

The OBD-II diagnostic service is implemented as a native C binary. It handles vehicle identification number (VIN) requests and updates. The VIN handling code may not properly validate input length, leading to a classic buffer overflow vulnerability.

### Objective

Trigger a buffer overflow in the OBD-II service by sending an oversized VIN request.

### Hints

- OBD-II uses a specific protocol format (Mode + PID bytes)
- VIN is typically 17 characters
- Mode 09 is used for vehicle information requests
- The service may not validate input length before copying to a fixed-size buffer
- Sending more than expected bytes may overflow the buffer
- The service is compiled without modern protections (no stack canary, executable stack)

### OBD-II Protocol Basics

| Byte | Description |
|------|-------------|
| 0 | Mode (e.g., 0x09 for vehicle info) |
| 1 | PID (e.g., 0x02 for VIN, 0x0A for VIN write) |
| 2+ | Data (if applicable) |

### Success Criteria

The validation API will return `success: true` when a buffer overflow attempt is detected (oversized request received).

**Note**: This is an advanced challenge that demonstrates real-world binary exploitation concepts. The service may crash after successful exploitation.

---

## V9: UDS Security Bypass (Fuzzing Required)

**Category**: Protocol Fuzzing
**Difficulty**: Hard
**Target**: UDS Gateway (TCP port 9556 or vcan0 CAN IDs 0x7DF/0x7E0-0x7E7)
**Validation Endpoint**: `GET /validate/uds_security_bypass`

### Description

The UDS (Unified Diagnostic Services) Gateway implements the standard ISO 14229 protocol used in automotive ECU diagnostics. The Security Access service (0x27) should require a proper seed-key exchange before granting elevated privileges. However, the implementation may have a state machine vulnerability that allows bypassing the authentication under specific conditions.

**This vulnerability requires stateful protocol fuzzing to discover.**

### Objective

Bypass the UDS Security Access authentication without providing a valid key.

### Hints

- UDS services have multiple sub-functions that may not all be documented
- State machine vulnerabilities often involve unexpected sequences of commands
- Consider what happens if sessions are established in non-standard ways
- The standard sub-functions for Security Access are 0x01 (requestSeed) and 0x02 (sendKey)
- Fuzzing tools like **Boofuzz** can generate protocol-aware test cases
- Try fuzzing sub-function values beyond the documented ones
- Session transitions may affect security state in unexpected ways

### UDS Protocol Basics

| Service | SID | Description |
|---------|-----|-------------|
| DiagnosticSessionControl | 0x10 | Change diagnostic session |
| SecurityAccess | 0x27 | Request security unlock |
| ReadDataByIdentifier | 0x22 | Read data from ECU |
| WriteDataByIdentifier | 0x2E | Write data to ECU |

**Session Types**: 0x01 (Default), 0x02 (Programming), 0x03 (Extended)

### Success Criteria

The validation API will return `success: true` when the security bypass is triggered.

---

## V10: CAN DLC Overflow (Fuzzing Required)

**Category**: Protocol Fuzzing
**Difficulty**: Hard
**Target**: CAN Frame Parser on vcan0
**Validation Endpoint**: `GET /validate/can_dlc_overflow`

### Description

The CAN Frame Parser service monitors the vcan0 interface for CAN traffic analysis. The vcan0 interface is configured with MTU 72 (CAN FD enabled), and the parser accepts CAN FD frames with data lengths up to 64 bytes. However, the parser copies frame data into a fixed 8-byte buffer using the length field without bounds checking, creating a buffer overflow vulnerability when CAN FD frames with more than 8 bytes of data are received.

**This vulnerability requires CAN FD frame fuzzing to discover.**

### Objective

Trigger a buffer overflow in the CAN Frame Parser by sending a CAN FD frame with more than 8 bytes of data.

### Hints

- Standard CAN frames have DLC values 0-8, but CAN FD allows up to 64 bytes
- The vcan0 interface has MTU 72 (CAN FD support is enabled)
- The parser accepts CAN FD frames but uses an 8-byte internal buffer
- Use `cansend` with CAN FD syntax: `cansend vcan0 <ID>##<flags>.<data>`
- Python's `python-can` library supports CAN FD with `is_fd=True`
- The overflow detection marker is logged before the memcpy, so it is captured even if the parser crashes

### CAN FD Frame Structure

| Field | Size | Description |
|-------|------|-------------|
| CAN ID | 4 bytes | Message identifier (11 or 29 bits) |
| Length | 1 byte | Data length (0-64 for CAN FD) |
| Data | 0-64 bytes | Payload data |

### Success Criteria

The validation API will return `success: true` when a DLC overflow is detected (parser logs the marker before the overflow occurs).

---

## V11: UDS Integer Overflow (Fuzzing Required)

**Category**: Protocol Fuzzing
**Difficulty**: Hard
**Target**: UDS Gateway (TCP port 9556 or vcan0)
**Validation Endpoint**: `GET /validate/uds_integer_overflow`

### Description

The UDS WriteDataByIdentifier service (0x2E) allows writing data to specific Data Identifiers (DIDs). The service calculates the data length from the request size. An integer overflow vulnerability may exist in the length calculation that could lead to a heap buffer overflow.

**This vulnerability requires fuzzing with malformed short requests to discover.**

### Objective

Trigger an integer overflow in the WriteDataByIdentifier service by sending a malformed request.

### Hints

- Integer overflows occur when arithmetic operations wrap around (e.g., 0 - 1 = 255 for uint8_t)
- Consider what happens when the request is shorter than expected
- The service expects: [SID][DID_hi][DID_lo][data...] (minimum 4 bytes)
- What if you send only 1 or 2 bytes?
- Fuzzing with various request lengths may reveal the vulnerability
- **Boofuzz** or similar tools can systematically test length boundaries

### WriteDataByIdentifier Format

| Byte | Description |
|------|-------------|
| 0 | SID (0x2E) |
| 1 | DID high byte |
| 2 | DID low byte |
| 3+ | Data to write |

### Success Criteria

The validation API will return `success: true` when an integer overflow is detected.

---

## V12: Firmware Header Overflow (Fuzzing Required)

**Category**: Protocol Fuzzing
**Difficulty**: Hard
**Target**: UDS Gateway (TCP port 9556 or vcan0)
**Validation Endpoint**: `GET /validate/uds_firmware_overflow`

### Description

The UDS Gateway supports firmware downloads via the RequestDownload (0x34), TransferData (0x36), and RequestTransferExit (0x37) services. The first TransferData block is parsed as a firmware header. A buffer overflow vulnerability exists in the header parsing that could be exploited through file format fuzzing.

**This vulnerability requires firmware format fuzzing to discover.**

### Objective

Trigger a buffer overflow in the firmware header parser by sending a malformed firmware header.

### Hints

- Firmware files often have headers with metadata (version, name, size)
- The header parser may have fixed-size buffers for string fields
- What happens if a length field claims more bytes than the buffer can hold?
- Mutation-based fuzzers like **Radamsa** are effective for file format fuzzing
- The firmware transfer requires: Programming Session (0x02) + Security Access unlocked
- First TransferData block (sequence 0x01) contains the firmware header

### UDS Transfer Flow

1. **RequestDownload (0x34)**: Initiate firmware transfer
2. **TransferData (0x36)**: Send firmware data blocks
3. **RequestTransferExit (0x37)**: Complete transfer

### Firmware Header Format (First TransferData Block)

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 4 bytes | Magic number |
| 4 | 2 bytes | Version |
| 6 | 2 bytes | Name length |
| 8 | N bytes | Firmware name |

### Success Criteria

The validation API will return `success: true` when a firmware header overflow is detected.

---

## Fuzzing Tools Reference

The following fuzzing tools are recommended for V9-V12 challenges:

| Tool | Use Case | Installation |
|------|----------|--------------|
| **Boofuzz** | Protocol-aware fuzzing (UDS, TCP) | `pip install boofuzz` |
| **Radamsa** | Mutation-based fuzzing (file formats) | Package manager or build from source |
| **python-can** | CAN frame manipulation | `pip install python-can` |
| **AFL/AFL++** | Coverage-guided fuzzing | Package manager or build from source |

Example fuzzing scripts are provided in `testbed/examples/`:
- `fuzz_uds_boofuzz.py` - UDS protocol fuzzing with Boofuzz
- `fuzz_can_frames.py` - CAN frame fuzzing with python-can
- `fuzz_firmware_radamsa.sh` - Firmware header fuzzing with Radamsa

**Note**: Fuzzing tools are not pre-installed in the container. Install them in your host environment and connect to the exposed ports.

---

## Validation API Reference

Check your progress using these endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /` | Health check |
| `GET /status` | Overall system and exploit status |
| `GET /validate/ssh_access` | Check V1 completion |
| `GET /validate/sqli_success` | Check V2 completion |
| `GET /validate/doors_unlocked` | Check V3 completion |
| `GET /validate/can_replay` | Check V4 completion |
| `GET /validate/directory_traversal` | Check V5 completion |
| `GET /validate/command_injection` | Check V6 completion |
| `GET /validate/idor` | Check V7 completion |
| `GET /validate/buffer_overflow` | Check V8 completion |
| `GET /validate/uds_security_bypass` | Check V9 completion |
| `GET /validate/can_dlc_overflow` | Check V10 completion |
| `GET /validate/uds_integer_overflow` | Check V11 completion |
| `GET /validate/uds_firmware_overflow` | Check V12 completion |
| `GET /logs?service=<name>&lines=<n>` | View service logs |
| `GET /fuzzing/crashes` | List detected crashes |
| `GET /fuzzing/status` | Fuzzing vulnerability status |
| `POST /fuzzing/reset` | Reset crash history |

Example status check:
```bash
curl http://localhost:9999/status | jq
```

Example fuzzing status check:
```bash
curl http://localhost:9999/fuzzing/status | jq
```
