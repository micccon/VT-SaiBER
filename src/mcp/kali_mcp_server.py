#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import logging
import sys
import os
from typing import Any, Dict, Optional

import requests
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = "http://localhost:5000" # change to your linux IP
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests

class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client
        
        Args:
            server_url: URL of the Kali Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters
            
        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a generic command on the Kali server
        
        Args:
            command: Command to execute
            
        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command})
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server
        
        Returns:
            Health status information
        """
        return self.safe_get("health")

def setup_mcp_server(kali_client: KaliToolsClient, host: str = "0.0.0.0", port: int = 5001) -> FastMCP:
    """
    Set up the MCP server with all tool functions
    
    Args:
        kali_client: Initialized KaliToolsClient
        
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("kali_mcp", host=host, port=port)
    
    @mcp.tool(name="nmap_scan")
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.
        
        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool(name="gobuster_scan")
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.
        
        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool(name="ffuf_scan")
    def ffuf_scan(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        match_codes: str = "200,204,301,302,307,401,403",
        rate_limit_delay: str = "0",
        threads: int = 10,
        timeout: int = 10,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """
        Execute ffuf (Fuzz Faster U Fool) web fuzzer for directory/file discovery.

        ffuf is faster and more configurable than gobuster. It outputs JSON for
        reliable machine-readable parsing. Use this as the primary web fuzzer.

        Args:
            url: The target base URL. FUZZ keyword is auto-injected if missing.
            wordlist: Path to wordlist file inside the Kali container.
                      Recommended: /usr/share/wordlists/dirb/common.txt (small, fast)
                                   /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt (thorough)
            match_codes: Comma-separated HTTP status codes to report (include).
                         Default covers success + auth + redirect codes.
                         Example: "200,301,403" to narrow findings.
            rate_limit_delay: Delay between requests in seconds (e.g. "0.2").
                              Set > 0 to avoid rate-limit bans. 0 means no delay.
            threads: Concurrent HTTP threads. Lower = safer/slower.
                     Recommended: 5-10 for testbed (avoids overloading target).
            timeout: Per-request HTTP timeout in seconds. Increase for slow targets.
            additional_args: Extra ffuf flags, e.g.:
                             "-e .php,.html" to probe extensions
                             "-recursion" for recursive scanning
                             "-fs 1234" to filter by response size (soft-404)
                             "-H 'Authorization: Bearer token'" for auth headers

        Returns:
            Raw ffuf JSON output with a 'results' list of discovered paths.
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "match_codes": match_codes,
            "rate_limit_delay": rate_limit_delay,
            "threads": threads,
            "timeout": timeout,
            "additional_args": additional_args,
        }
        return kali_client.safe_post("api/tools/ffuf", data)

    @mcp.tool(name="dirb_scan")
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool(name="nikto_scan")
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool(name="sqlmap_scan")
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            
        Returns:
            Scan results
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool(name="metasploit_run")
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.
        
        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            
        Returns:
            Module execution results
        """
        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool(name="hydra_attack")
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool(name="john_crack")
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool(name="wpscan_analyze")
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.
        
        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool(name="enum4linux_scan")
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.
        
        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            
        Returns:
            Enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/enum4linux", data)

    @mcp.tool(name="server_health")
    def server_health() -> Dict[str, Any]:
        """Check the health status of the Kali API server."""
        return kali_client.check_health()

    @mcp.tool(name="execute_command")
    def execute_command(command: str) -> Dict[str, Any]:
        """Execute an arbitrary command on the Kali server."""
        return kali_client.execute_command(command)

    # -----------------------------------------------------------------------
    # CAN Bus / Automotive OT Tools
    # -----------------------------------------------------------------------

    @mcp.tool(name="can_dump")
    def can_dump(
        interface: str = "vcan0",
        count: int = 100,
        duration: int = 5,
        filter: str = "",
    ) -> Dict[str, Any]:
        """
        Capture CAN bus frames from a virtual or physical CAN interface.

        Uses ``candump`` from can-utils.  Returns raw frame output suitable
        for ``parse_candump_output`` in the automotive agent.

        ICSim vcan0 traffic example::

            vcan0  244   [8]  00 00 00 00 00 00 00 32   # speedometer
            vcan0  188   [8]  00 00 00 00 00 00 00 00   # turn signals
            vcan0  19B   [8]  00 00 00 00 00 00 00 00   # doors

        Args:
            interface: CAN interface name (e.g. ``vcan0``, ``can0``).
            count:     Maximum number of frames to capture.
            duration:  Capture time limit in seconds.
            filter:    Optional candump filter expression (``200:7FF``, ``244#~``).

        Returns:
            Raw candump output with one frame per line.
        """
        data = {
            "interface": interface,
            "count": count,
            "duration": duration,
            "filter": filter,
        }
        return kali_client.safe_post("api/tools/candump", data)

    @mcp.tool(name="can_send")
    def can_send(
        frame: str,
        interface: str = "vcan0",
        repeat: int = 1,
        delay_ms: int = 0,
    ) -> Dict[str, Any]:
        """
        Inject a CAN frame onto the bus.

        Uses ``cansend`` from can-utils.  The frame must be in the standard
        ``ID#DATA`` hex format understood by cansend.

        ICSim CAN IDs (reference)
        -------------------------
        - ``244#<8-byte-hex>`` : Speedometer.  Byte 3 controls speed value
                                 (0x00 = 0 mph, 0xFF = max speed ~130 mph).
                                 Example: ``244#0000000000000032`` → 50 mph
        - ``188#<8-byte-hex>`` : Turn signals.  Byte 0 bit 0 = right signal,
                                 bit 1 = left signal.
        - ``19B#<8-byte-hex>`` : Door locks. Each nibble = one door.
                                 0x01 = driver door, 0x02 = passenger, etc.

        Args:
            frame:      CAN frame string: ``<HEX_ID>#<HEX_DATA>``
                        e.g. ``244#0000000000000064`` (100 mph speedometer)
            interface:  CAN interface name (default ``vcan0``).
            repeat:     Number of times to send the frame.
            delay_ms:   Milliseconds between repeated frames.

        Returns:
            Success status and number of frames actually sent.
        """
        data = {
            "frame": frame,
            "interface": interface,
            "repeat": repeat,
            "delay_ms": delay_ms,
        }
        return kali_client.safe_post("api/tools/cansend", data)

    @mcp.tool(name="can_discover")
    def can_discover(
        interface: str = "vcan0",
        duration: int = 3,
    ) -> Dict[str, Any]:
        """
        Passively capture the CAN bus to discover active arbitration IDs.

        Runs ``candump`` for ``duration`` seconds and returns all frames
        seen.  The automotive agent parses this output to build a baseline
        of active CAN IDs before starting differential analysis.

        Args:
            interface: CAN interface name (default ``vcan0``).
            duration:  Passive capture time in seconds (default 3).

        Returns:
            Raw candump output containing all observed CAN frames.
        """
        data = {
            "interface": interface,
            "duration": duration,
        }
        return kali_client.safe_post("api/tools/can_discover", data)

    return mcp


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the MCP Kali client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                      help="Host to bind MCP server (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5001,
                      help="Port to bind MCP server (default: 5001)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")
    
    # Set up the MCP server
    mcp = setup_mcp_server(kali_client, host=args.host, port=args.port)
    
    logger.info(f"Starting MCP Kali server on {args.host}:{args.port}")
    mcp.run(transport="sse")

if __name__ == "__main__":
    main()