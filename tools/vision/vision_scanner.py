"""
wrapper for the nmap command-line tool

this module is responsible for:
2.  Executing an nmap command as a subprocess
2.  Returning a vision scan result object from scans
"""
import subprocess 
from tools.vision.vision_scan_result import VisionScanResult
from tools.vision.vision_parser import VisionParser
import sys
import os
import shutil
from pathlib import Path

# Add project root to sys.path
project_root = str(Path(__file__).parent.parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)


# class that the MCP class uses to complete scans
class VisionScanner:

    # timeout: scan runs longer than 120 seconds cut it
    # nmap_path: for potential future docker implementation, sets default nmap path
    def __init__(self, timeout: int = 120, nmap_path: str = None):
        self.timeout = timeout
        self.nmap_path = nmap_path or self._resolve_nmap_path()
        self.is_available = True
        self._verify_nmap()

    def _resolve_nmap_path(self) -> str:
        """Resolve nmap path from env var, PATH, or common locations."""
        # 1. Check environment variable
        env_path = os.environ.get("NMAP_PATH")
        if env_path and os.path.exists(env_path):
            return env_path
            
        # 2. Check system PATH
        which_path = shutil.which("nmap")
        if which_path:
            return which_path
            
        # 3. Check common locations
        common_paths = [
            "/usr/local/bin/nmap",
            "/opt/homebrew/bin/nmap",
            "/usr/bin/nmap",
            "/bin/nmap"
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path
                
        # Default fallback
        return "nmap"

    # Verify nmap is installed and can run
    def _verify_nmap(self) -> None:
        try:
            subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                check=True,
                timeout=5
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            # Instead of raising error, mark as unavailable
            self.is_available = False
            # We don't raise here to allow the app to start
            # raise RuntimeError(f"nmap not found at {self.nmap_path}")
        
    # Modular scan that tools exposed to mcp will use
    def scan(self, target: str, scan_type: str = "custom", *args) -> VisionScanResult:
        
        # Start time for duration portions
        import time
        start_time = time.time()

        if not self.is_available:
            return VisionScanResult(
                success=False,
                tool_name="nmap",
                target=target,
                scan_type=scan_type,
                hosts=[],
                error=f"nmap not found at {self.nmap_path}. Please install nmap.",
                duration=0
            )

        # command that nmap will run
        cmd = [self.nmap_path, "-oX", "-"] + list(args) + [target]

        try: # Run the nmap scan
            result = subprocess.run(
                cmd,
                capture_output = True,
                text = True,
                timeout = self.timeout
            )

            # calculate duration time
            duration = time.time() - start_time

            # If the scan didn't run
            if result.returncode != 0:
                return VisionScanResult(
                    success= False,
                    tool_name="nmap",
                    target = target,
                    scan_type = scan_type,
                    hosts = [],
                    error = result.stderr,
                    command = " ".join(cmd),
                    duration = duration
                )
            
            # parse the data with my loooovvvveeeellllyyy parser
            parsed_data = VisionParser.parse_xml(result.stdout)
            
            # returns a vision scan result object (lfg)
            return VisionScanResult(
                success=True,
                tool_name="nmap",
                target=target,
                scan_type=scan_type,
                hosts=parsed_data.get("hosts", []),
                command=" ".join(cmd),
                duration=duration
            )
        # if it took too long
        except subprocess.TimeoutExpired:
            return VisionScanResult(
                success=False,
                tool_name="nmap",
                target=target,
                scan_type=scan_type,
                hosts=[],
                error=f"Scan timed out after {self.timeout} seconds",
                duration=self.timeout
            )
        # if anything else went wrong
        except Exception as e:
            return VisionScanResult(
                success=False,
                tool_name="nmap",
                target=target,
                scan_type=scan_type,
                hosts=[],
                error=f"Unexpected error: {str(e)}",
                duration=time.time() - start_time
            )

# If you want to test urself uncomment these
# But I wrote a simple test method in the mcp sooooo

# vision = VisionNmapScanner()
# result = vision.scan("scanme.nmap.org", "-F")
# print(json.dumps(asdict(result), indent=2))