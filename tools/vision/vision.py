"""
wrapper for the nmap command-line tool

this module is responsible for:
2.  Executing an nmap command as a subprocess
2.  Returning a vision scan result object from scans
"""
import subprocess 
from vision_scan_result import VisionScanResult
from vision_parser import VisionParser


# class that the MCP class uses to complete scans
class VisionNmapScanner:

    # timeout: scan runs longer than 120 seconds cut it
    # nmap_path: for potential future docker implementation, sets default nmap path
    def __init__(self, timeout: int = 120, nmap_path: str = "nmap"):
        self.timeout = timeout
        self.nmap_path = nmap_path
        self._verify_nmap()

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
            raise RuntimeError(f"nmap not found at {self.nmap_path}")
        
    # Modular scan that tools exposed to mcp will use
    def scan(self, target: str, scan_type: str = "custom", *args) -> VisionScanResult:
        
        # Start time for duration portions
        import time
        start_time = time.time()

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
                target=target,
                scan_type=scan_type,
                hosts=parsed_data.get("hosts", []),
                command=" ".join(cmd),
                duration=duration
            )
        # if it took too long (wtf u scannin bruh)
        except subprocess.TimeoutExpired:
            return VisionScanResult(
                success=False,
                target=target,
                scan_type=scan_type,
                hosts=[],
                error=f"Scan timed out after {self.timeout} seconds",
                duration=self.timeout
            )
        # if anything else went wrong (kinda lazy tbh my bad)
        except Exception as e:
            return VisionScanResult(
                success=False,
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