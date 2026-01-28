"""
LangGraph Tools for Vision Network Scanning

This module exposes nmap scanning functionality as LangChain/LangGraph tools.
Usage in LangGraph:
    from tools.vision.vision_tools import vision_tools
    tool_node = ToolNode(vision_tools)
"""

from typing import Optional
from langchain_core.tools import tool
from tools.vision.vision_scanner import VisionScanner

# Initialize the scanner (reusable across tool calls)
# Note: In a container, ensure nmap is installed and in PATH
_scanner = VisionScanner(timeout=120)


@tool
async def ping_scan(target: str) -> dict:
    """
    Discover live hosts without port scanning. Fastest option for initial reconnaissance. 
    Use this before deeper scans to identify which hosts are up. Works on CIDR ranges. 
    Note: Some hosts may block ICMP.
    
    Args:
        target: IP address, hostname, or CIDR range (e.g., "192.168.1.1", "10.0.0.0/24")
    """
    result = await _scanner.scan(target, "ping", "-sn")
    return result.to_dict()


@tool
async def quick_scan(target: str) -> dict:
    """
    Scan top 100 most common ports with aggressive timing. Good balance of speed and coverage 
    for initial port discovery. Use when you need quick results without scanning all 65k ports.
    
    Args:
        target: IP address or hostname to scan (e.g., "192.168.1.1", "scanme.nmap.org")
    """
    result = await _scanner.scan(target, "quick", "-F", "-T4")
    return result.to_dict()


@tool
async def port_scan(target: str, ports: str) -> dict:
    """
    Scan specific ports or ranges. Use when you know which ports to check (e.g., web server on 80/443, SSH on 22). 
    Supports single ports, ranges (1-1000), and comma-separated lists (22,80,443,8080).
    
    Args:
        target: IP address, hostname, or CIDR range
        ports: Port specification (e.g., "22", "1-1000", "22,80,443")
    """
    result = await _scanner.scan(target, "port", "-p", ports)
    return result.to_dict()


@tool
async def service_scan(target: str, ports: Optional[str] = None) -> dict:
    """
    Identify service versions on open ports (e.g., Apache 2.4.1, OpenSSH 8.2). Critical for vulnerability assessment. 
    Slower than basic port scan but provides detailed software information. Optionally limit to specific ports.
    
    Args:
        target: IP address or hostname to scan
        ports: Optional port specification to limit scanning (e.g., "1-1000", "22,80,443")
    """
    args = ["-sV"]
    if ports:
        args.extend(["-p", ports])
    result = await _scanner.scan(target, "service", *args)
    return result.to_dict()


@tool
async def comprehensive_scan(target: str) -> dict:
    """
    Most thorough scan: OS detection, version detection, script scanning, and traceroute. 
    Use for complete security assessment of a single host. 
    WARNING: Very noisy and highly detectable - will trigger IDS/IPS. Takes longest to complete.
    
    Args:
        target: IP address or hostname (single target recommended)
    """
    result = await _scanner.scan(target, "comprehensive", "-A", "-T4")
    return result.to_dict()


@tool
async def stealth_scan(target: str, ports: Optional[str] = None) -> dict:
    """
    Stealth SYN scan that's harder to detect than normal scans. Uses half-open connections that are less likely to be logged. 
    REQUIRES root/admin privileges. Use when you need to avoid triggering security alerts.
    
    Args:
        target: IP address, hostname, or CIDR range
        ports: Optional port specification (e.g., "1-1000", "22,80,443")
    """
    args = ["-sS"]
    if ports:
        args.extend(["-p", ports])
    result = await _scanner.scan(target, "stealth", *args)
    return result.to_dict()


@tool
async def udp_scan(target: str, ports: Optional[str] = None) -> dict:
    """
    Scan UDP ports to find services like DNS (53), SNMP (161), or NTP (123). 
    UDP scans are very slow due to protocol limitations. Use sparingly or target specific known UDP ports. 
    Often misses services due to lack of response.
    
    Args:
        target: IP address, hostname, or CIDR range
        ports: Optional port specification (e.g., "53", "161", "1-1000")
    """
    args = ["-sU"]
    if ports:
        args.extend(["-p", ports])
    result = await _scanner.scan(target, "udp", *args)
    return result.to_dict()


@tool
async def full_tcp_scan(target: str) -> dict:
    """
    Scan all 65,535 TCP ports for complete coverage. Takes significantly longer than quick_scan but ensures no services are missed. 
    Use for thorough security audits when time isn't critical. Recommended for single hosts only.
    
    Args:
        target: IP address or hostname
    """
    result = await _scanner.scan(target, "full_tcp", "-p-", "-T4")
    return result.to_dict()


@tool
async def os_scan(target: str) -> dict:
    """
    Detect operating system using TCP/IP fingerprinting. Returns OS guesses with confidence levels (e.g., 'Linux 3.x-4.x (95%)'). 
    Useful for inventory and vulnerability correlation. Less intrusive than comprehensive_scan.
    
    Args:
        target: IP address or hostname
    """
    result = await _scanner.scan(target, "os", "-O")
    return result.to_dict()


@tool
async def script_scan(target: str, script: str = "default") -> dict:
    """
    Run Nmap Scripting Engine scripts for advanced reconnaissance. 
    Only safe scripts allowed: 'default', 'safe', 'discovery', 'version', 'http-*', 'ssl-*', 'ssh-*', 'smb-enum*'. 
    Use 'default' for general info, 'ssl-*' for certificate details, 'http-*' for web server info.
    
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
    
    result = await _scanner.scan(target, "script", "--script", script)
    return result.to_dict()

# Export list of tools for LangGraph ToolNode
vision_tools = [
    ping_scan,
    quick_scan,
    port_scan,
    service_scan,
    comprehensive_scan,
    stealth_scan,
    udp_scan,
    full_tcp_scan,
    os_scan,
    script_scan
]