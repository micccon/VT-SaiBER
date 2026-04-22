# Automotive Pentesting Testbed

A Docker-based environment simulating a vulnerable automotive system for penetration testing practice.

## Platform Requirements

| Platform | Support |
|----------|---------|
| Native Linux | Full |
| Linux VM (VirtualBox/VMware) | Full |
| WSL2 | Partial (no CAN bus) |
| macOS (Docker Desktop) | Partial (no CAN bus) |

CAN bus challenges require the `vcan` kernel module (native Linux only).

## Quick Start

```bash
# Build and start the testbed
docker-compose up -d

# Verify the container is running
docker ps

# Check system status
curl http://localhost:9999/status | jq
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| SSH Server | 2222 | Gateway SSH access |
| Infotainment | 8000 | Web-based portal |
| Gateway | 8080 | Firmware management service |
| OBD-II Server | 9555 | Vehicle diagnostics interface |
| UDS Gateway | 9556 | UDS protocol gateway (TCP + CAN/vcan0) |
| CAN Frame Parser | vcan0 | CAN bus frame monitoring (CAN FD enabled) |
| Validation API | 9999 | Status and validation endpoints |

## Validation API

The validation API helps you track your progress.

```bash
# Health check
curl http://localhost:9999/

# System status (shows exploit completion)
curl http://localhost:9999/status | jq

# View service logs
curl "http://localhost:9999/logs?service=gateway&lines=20" | jq
curl "http://localhost:9999/logs?service=infotainment&lines=20" | jq
```

## CAN Bus Tools

If you're on native Linux, the container includes CAN utilities:

```bash
# Access the container shell
docker exec -it automotive-testbed bash

# Monitor CAN traffic
candump vcan0

# Send CAN messages
cansend vcan0 <arbitration_id>#<data>
```

## Stopping the Testbed

```bash
docker-compose down
```

## Validate Your Setup

```bash
docker exec automotive-testbed /opt/automotive-testbed/validate_setup.sh
```

## Troubleshooting

**Container won't start:**
- Ensure Docker is running
- Check that ports 2222, 8000, 8080, 9555, 9556, 9999 are available

**CAN commands fail:**
- WSL2/macOS: CAN is not supported
- Native Linux: Run `sudo modprobe vcan` first

**API not responding:**
- Check container status: `docker ps`
- View logs: `docker-compose logs`
