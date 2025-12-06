"""
FastMCP Server for Vision Network Scanning Tools

This MCP server exposes nmap scanning functionality to Strands agents.
Run with: python mcp_server.py

The server will start on http://localhost:8000 with SSE transport.
"""

import sys
from pathlib import Path

# Add project root to sys.path
project_root = str(Path(__file__).parent.parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

from fastmcp import FastMCP
from typing import Optional
from tools.vision.vision_scanner import VisionScanner

# Initialize the MCP server
mcp = FastMCP("Vision Network Scanner")

# Initialize the scanner (reusable across tool calls)
_scanner = VisionScanner(timeout=120)


@mcp.tool(description="Discover live hosts without port scanning. Fastest option for initial reconnaissance. Use this before deeper scans to identify which hosts are up. Works on CIDR ranges. Note: Some hosts may block ICMP.")
def ping_scan(target: str) -> dict:
    """
    Args:
        target: IP address, hostname, or CIDR range (e.g., "192.168.1.1", "10.0.0.0/24")
    """
    result = _scanner.scan(target, "ping", "-sn")
    return result.to_dict()


@mcp.tool(description="Scan top 100 most common ports with aggressive timing. Good balance of speed and coverage for initial port discovery. Use when you need quick results without scanning all 65k ports.")
def quick_scan(target: str) -> dict:
    """
    Args:
        target: IP address or hostname to scan (e.g., "192.168.1.1", "scanme.nmap.org")
    """
    result = _scanner.scan(target, "quick", "-F", "-T4")
    return result.to_dict()


@mcp.tool(description="Scan specific ports or ranges. Use when you know which ports to check (e.g., web server on 80/443, SSH on 22). Supports single ports, ranges (1-1000), and comma-separated lists (22,80,443,8080).")
def port_scan(target: str, ports: str) -> dict:
    """
    Args:
        target: IP address, hostname, or CIDR range
        ports: Port specification (e.g., "22", "1-1000", "22,80,443")
    """
    result = _scanner.scan(target, "port", "-p", ports)
    return result.to_dict()


@mcp.tool(description="Identify service versions on open ports (e.g., Apache 2.4.1, OpenSSH 8.2). Critical for vulnerability assessment. Slower than basic port scan but provides detailed software information. Optionally limit to specific ports.")
def service_scan(target: str, ports: Optional[str] = None) -> dict:
    """
    Args:
        target: IP address or hostname to scan
        ports: Optional port specification to limit scanning (e.g., "1-1000", "22,80,443")
    """
    args = ["-sV"]
    if ports:
        args.extend(["-p", ports])
    result = _scanner.scan(target, "service", *args)
    return result.to_dict()


@mcp.tool(description="Most thorough scan: OS detection, version detection, script scanning, and traceroute. Use for complete security assessment of a single host. WARNING: Very noisy and highly detectable - will trigger IDS/IPS. Takes longest to complete.")
def comprehensive_scan(target: str) -> dict:
    """
    WARNING: This scan is highly detectable and may trigger security alerts.
    
    Args:
        target: IP address or hostname (single target recommended)
    """
    result = _scanner.scan(target, "comprehensive", "-A", "-T4")
    return result.to_dict()


@mcp.tool(description="Stealth SYN scan that's harder to detect than normal scans. Uses half-open connections that are less likely to be logged. REQUIRES root/admin privileges. Use when you need to avoid triggering security alerts.")
def stealth_scan(target: str, ports: Optional[str] = None) -> dict:
    """
    REQUIRES: Administrator/root privileges for raw packet sending.
    
    Args:
        target: IP address, hostname, or CIDR range
        ports: Optional port specification (e.g., "1-1000", "22,80,443")
    """
    args = ["-sS"]
    if ports:
        args.extend(["-p", ports])
    result = _scanner.scan(target, "stealth", *args)
    return result.to_dict()


@mcp.tool(description="Scan UDP ports to find services like DNS (53), SNMP (161), or NTP (123). UDP scans are very slow due to protocol limitations. Use sparingly or target specific known UDP ports. Often misses services due to lack of response.")
def udp_scan(target: str, ports: Optional[str] = None) -> dict:
    """
    Args:
        target: IP address, hostname, or CIDR range
        ports: Optional port specification (e.g., "53", "161", "1-1000")
    """
    args = ["-sU"]
    if ports:
        args.extend(["-p", ports])
    result = _scanner.scan(target, "udp", *args)
    return result.to_dict()


@mcp.tool(description="Scan all 65,535 TCP ports for complete coverage. Takes significantly longer than quick_scan but ensures no services are missed. Use for thorough security audits when time isn't critical. Recommended for single hosts only.")
def full_tcp_scan(target: str) -> dict:
    """
    Args:
        target: IP address or hostname
    """
    result = _scanner.scan(target, "full_tcp", "-p-", "-T4")
    return result.to_dict()


@mcp.tool(description="Detect operating system using TCP/IP fingerprinting. Returns OS guesses with confidence levels (e.g., 'Linux 3.x-4.x (95%)' or 'Windows 10 (89%)'). Useful for inventory and vulnerability correlation. Less intrusive than comprehensive_scan.")
def os_scan(target: str) -> dict:
    """
    Args:
        target: IP address or hostname
    """
    result = _scanner.scan(target, "os", "-O")
    return result.to_dict()


@mcp.tool(description="Run Nmap Scripting Engine scripts for advanced reconnaissance. Only safe scripts allowed: 'default', 'safe', 'discovery', 'version', 'http-*', 'ssl-*', 'ssh-*', 'smb-enum*'. Use 'default' for general info, 'ssl-*' for certificate details, 'http-*' for web server info.")
def script_scan(target: str, script: str = "default") -> dict:
    """
    Allowed scripts: default, safe, discovery, version, http-*, ssl-*, ssh-*, smb-enum*
    
    Args:
        target: IP address or hostname
        script: NSE script or category to run (default: "default")
    """
    # Allowlist for safety
    allowed_scripts = [
        "default", "safe", "discovery", "version",
        "http-*", "ssl-*", "ssh-*", "smb-enum*"
    ]
    
    # Check if script matches any allowed pattern
    script_allowed = any(
        script == allowed or 
        (allowed.endswith("*") and script.startswith(allowed[:-1]))
        for allowed in allowed_scripts
    )
    
    if not script_allowed:
        return {
            "success": False,
            "tool_name": "nmap",
            "target": target,
            "scan_type": "script",
            "hosts": [],
            "error": f"Script '{script}' not in allowlist. Allowed: {', '.join(allowed_scripts)}"
        }
    
    result = _scanner.scan(target, "script", "--script", script)
    return result.to_dict()


if __name__ == "__main__":
    # Run the server with SSE transport on localhost:8000
    print("🚀 Starting Vision MCP Server on http://localhost:8000")
    print("📡 Transport: Server-Sent Events (SSE)")
    print("🔧 Tools: 11 network scanning tools available")
    print("\nPress Ctrl+C to stop the server\n")
    
    mcp.run(transport="sse", host="0.0.0.0", port=8000)