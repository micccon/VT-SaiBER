#!/usr/bin/env python3
"""
Supervisord Event Listener for Crash Detection

This script monitors supervisord events (PROCESS_STATE_EXITED and PROCESS_STATE_FATAL)
and logs crashes to /var/log/automotive-pentest/crashes.log in JSON format.

Targeted services: uds-gateway, can-parser (fuzzing targets)
"""

import sys
import json
import os
from datetime import datetime

# Log file path for crash detection
CRASHES_LOG = '/var/log/automotive-pentest/crashes.log'

# Services to monitor for crash detection
MONITORED_SERVICES = ['uds-gateway', 'can-parser', 'obd']

# Vulnerability mapping for each service
SERVICE_VULNERABILITY_MAP = {
    'uds-gateway': ['V9', 'V11', 'V12'],
    'can-parser': ['V10'],
    'obd': ['V8']
}


def write_stderr(message):
    """Write message to stderr for debugging."""
    sys.stderr.write(message + '\n')
    sys.stderr.flush()


def log_crash(service, exit_code, crash_type, event_data):
    """Log crash event to crashes.log in JSON format."""
    crash_record = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'service': service,
        'exit_code': exit_code,
        'crash_type': crash_type,
        'potential_vulnerabilities': SERVICE_VULNERABILITY_MAP.get(service, []),
        'event_data': event_data
    }

    # Ensure log directory exists
    log_dir = os.path.dirname(CRASHES_LOG)
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError:
            pass  # Directory may already exist

    # Append crash record to log file
    try:
        with open(CRASHES_LOG, 'a') as f:
            f.write(json.dumps(crash_record) + '\n')
    except IOError as e:
        write_stderr(f'Error writing to crashes.log: {e}')


def parse_event_data(data_line):
    """Parse supervisord event data into a dictionary."""
    event_data = {}
    pairs = data_line.split()
    for pair in pairs:
        if ':' in pair:
            key, value = pair.split(':', 1)
            event_data[key] = value
    return event_data


def handle_event(headers, payload):
    """Handle a supervisord event."""
    event_name = headers.get('eventname', '')

    # Only process PROCESS_STATE events we care about
    if event_name not in ('PROCESS_STATE_EXITED', 'PROCESS_STATE_FATAL'):
        return

    # Parse the payload
    event_data = parse_event_data(payload)
    process_name = event_data.get('processname', '')

    # Only monitor specific services
    if process_name not in MONITORED_SERVICES:
        return

    # Determine crash type
    if event_name == 'PROCESS_STATE_EXITED':
        # Check if it was expected (normal exit) or unexpected (crash)
        expected = event_data.get('expected', '0')
        if expected == '1':
            return  # Normal expected exit, not a crash
        crash_type = 'unexpected_exit'
    elif event_name == 'PROCESS_STATE_FATAL':
        crash_type = 'fatal'
    else:
        crash_type = 'unknown'

    # Get exit code
    exit_code_str = event_data.get('exitcode', '-1')
    try:
        exit_code = int(exit_code_str)
    except ValueError:
        exit_code = -1

    # Log the crash
    log_crash(process_name, exit_code, crash_type, event_data)
    write_stderr(f'CRASH DETECTED: {process_name} ({crash_type}, exit_code={exit_code})')


def main():
    """Main event listener loop."""
    write_stderr('Crash monitor starting...')

    while True:
        # Write READY to indicate we're ready for events
        sys.stdout.write('READY\n')
        sys.stdout.flush()

        # Read header line
        line = sys.stdin.readline()
        if not line:
            break

        # Parse headers
        headers = {}
        header_pairs = line.strip().split()
        for pair in header_pairs:
            if ':' in pair:
                key, value = pair.split(':', 1)
                headers[key] = value

        # Read payload (length is in headers)
        data_len = int(headers.get('len', 0))
        payload = ''
        if data_len > 0:
            payload = sys.stdin.read(data_len)

        # Handle the event
        handle_event(headers, payload)

        # Write RESULT to acknowledge event
        sys.stdout.write('RESULT 2\nOK')
        sys.stdout.flush()


if __name__ == '__main__':
    main()
