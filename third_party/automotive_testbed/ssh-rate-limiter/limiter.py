#!/usr/bin/env python3
"""
SSH Rate Limiter - Fail2ban style protection for SSH
Monitors SSH authentication logs and blocks IPs after repeated failures.

Configuration:
- MAX_FAILURES: 3 failures triggers lockout
- LOCKOUT_SECONDS: 30 second lockout period
"""
import os
import re
import subprocess
import time
import threading
from collections import defaultdict

# Configuration
MAX_FAILURES = 3
LOCKOUT_SECONDS = 30
LOG_PATH = '/var/log/automotive-pentest/sshd.log'
CHECK_INTERVAL = 1  # Check log every 1 second
RATE_LIMIT_LOG = '/var/log/automotive-pentest/ssh-rate-limit.log'

# In-memory tracking
failure_counts = defaultdict(list)  # IP -> list of failure timestamps
blocked_ips = {}  # IP -> unblock timestamp
lock = threading.Lock()


def log_message(message):
    """Write a message to the rate limit log file."""
    try:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        with open(RATE_LIMIT_LOG, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
        print(f"[{timestamp}] {message}")
    except Exception as e:
        print(f"Logging error: {e}")


def block_ip(ip_address):
    """Block an IP address using iptables."""
    try:
        # Add iptables rule to drop connections from this IP to port 22
        subprocess.run(
            ['iptables', '-A', 'INPUT', '-s', ip_address, '-p', 'tcp', '--dport', '22', '-j', 'DROP'],
            check=True,
            capture_output=True
        )
        log_message(f"SSH_RATE_LIMIT_BLOCKED: Blocked IP {ip_address} for {LOCKOUT_SECONDS}s after {MAX_FAILURES} failed attempts")
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"Failed to block IP {ip_address}: {e}")
        return False
    except FileNotFoundError:
        log_message(f"SSH_RATE_LIMIT_BLOCKED: (iptables not available) Would block IP {ip_address} for {LOCKOUT_SECONDS}s")
        return True  # Still track as blocked for testing


def unblock_ip(ip_address):
    """Unblock an IP address by removing the iptables rule."""
    try:
        subprocess.run(
            ['iptables', '-D', 'INPUT', '-s', ip_address, '-p', 'tcp', '--dport', '22', '-j', 'DROP'],
            check=True,
            capture_output=True
        )
        log_message(f"SSH_RATE_LIMIT_UNBLOCKED: Unblocked IP {ip_address}")
        return True
    except subprocess.CalledProcessError:
        # Rule might not exist, that's okay
        return True
    except FileNotFoundError:
        log_message(f"SSH_RATE_LIMIT_UNBLOCKED: (iptables not available) Would unblock IP {ip_address}")
        return True


def record_failure(ip_address):
    """Record a failed authentication attempt and check if blocking is needed."""
    current_time = time.time()
    window_start = current_time - LOCKOUT_SECONDS

    with lock:
        # Check if already blocked
        if ip_address in blocked_ips:
            if current_time < blocked_ips[ip_address]:
                return  # Still blocked, ignore
            else:
                # Lockout expired, unblock
                unblock_ip(ip_address)
                del blocked_ips[ip_address]
                failure_counts[ip_address] = []

        # Clean up old failures outside the window
        failure_counts[ip_address] = [
            ts for ts in failure_counts[ip_address]
            if ts > window_start
        ]

        # Record this failure
        failure_counts[ip_address].append(current_time)
        log_message(f"SSH_AUTH_FAILURE: IP {ip_address} - attempt {len(failure_counts[ip_address])}/{MAX_FAILURES}")

        # Check if threshold exceeded
        if len(failure_counts[ip_address]) >= MAX_FAILURES:
            blocked_ips[ip_address] = current_time + LOCKOUT_SECONDS
            block_ip(ip_address)
            failure_counts[ip_address] = []  # Reset counter after blocking


def check_blocked_ips():
    """Periodically check and unblock IPs whose lockout has expired."""
    current_time = time.time()
    with lock:
        ips_to_unblock = [
            ip for ip, unblock_time in blocked_ips.items()
            if current_time >= unblock_time
        ]
        for ip in ips_to_unblock:
            unblock_ip(ip)
            del blocked_ips[ip]


def parse_ssh_log_line(line):
    """
    Parse an SSH log line and extract IP address if it's a failed auth.
    Returns IP address or None.

    SSH failure patterns:
    - "Failed password for <user> from <IP> port <port>"
    - "Failed password for invalid user <user> from <IP> port <port>"
    - "Invalid user <user> from <IP> port <port>"
    - "Connection closed by authenticating user <user> <IP> port <port>"
    """
    # Pattern for failed password attempts
    failed_patterns = [
        r'Failed password for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+)',
        r'Invalid user \S+ from (\d+\.\d+\.\d+\.\d+)',
        r'Connection closed by authenticating user \S+ (\d+\.\d+\.\d+\.\d+)',
        r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)',
    ]

    for pattern in failed_patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return None


def monitor_log():
    """Monitor the SSH log file for authentication failures."""
    log_message("SSH Rate Limiter started")
    log_message(f"Config: {MAX_FAILURES} failures in {LOCKOUT_SECONDS}s triggers {LOCKOUT_SECONDS}s lockout")

    # Track file position for incremental reading
    last_position = 0
    last_inode = None

    while True:
        try:
            # Check for expired blocks
            check_blocked_ips()

            # Check if log file exists
            if not os.path.exists(LOG_PATH):
                time.sleep(CHECK_INTERVAL)
                continue

            # Check if file was rotated (new inode)
            current_inode = os.stat(LOG_PATH).st_ino
            if last_inode and current_inode != last_inode:
                last_position = 0
                log_message("Log file rotated, starting from beginning")
            last_inode = current_inode

            # Read new lines from log
            with open(LOG_PATH, 'r') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                last_position = f.tell()

            # Process each new line
            for line in new_lines:
                ip_address = parse_ssh_log_line(line)
                if ip_address:
                    record_failure(ip_address)

        except Exception as e:
            log_message(f"Error in monitor loop: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == '__main__':
    monitor_log()
