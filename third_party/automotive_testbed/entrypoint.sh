#!/bin/bash
# Entrypoint script for Automotive Pentesting Testbed
# Sets up virtual CAN interface before starting supervisord

set -e

# Load the vcan kernel module (may already be loaded by host)
modprobe vcan 2>/dev/null || true

# Create vcan0 interface if it doesn't already exist
if ! ip link show vcan0 >/dev/null 2>&1; then
    ip link add dev vcan0 type vcan
    ip link set vcan0 mtu 72
    echo "Created vcan0 interface (MTU=72 for CAN FD)"
else
    ip link set vcan0 mtu 72 2>/dev/null || true
    echo "vcan0 interface already exists"
fi

# Bring up the vcan0 interface
ip link set up vcan0
echo "vcan0 interface is UP"

# Ensure utmp exists for 'who' command (SSH validation)
touch /var/run/utmp
chmod 664 /var/run/utmp

# Start supervisord as PID 1
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
