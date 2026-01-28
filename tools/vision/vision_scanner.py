"""
wrapper for the nmap command-line tool

this module is responsible for:
1.  Executing an nmap command as an async subprocess
2.  Returning a vision scan result object from scans
3.  Handling safe cancellation/interruption of scans
"""
import asyncio
import shutil
import os
import time
from typing import List

from tools.vision.vision_scan_result import VisionScanResult
from tools.vision.vision_parser import VisionParser

class VisionScanner:

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

    def _verify_nmap(self) -> None:
        try:
            import subprocess
            subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                check=True,
                timeout=5
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            self.is_available = False
        
    async def scan(self, target: str, scan_type: str = "custom", *args) -> VisionScanResult:
        
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

        nmap_args = ["-oX", "-"] + list(args) + [target]
        command_str = f"{self.nmap_path} {' '.join(nmap_args)}"
        process = None

        try: 
            # Run the nmap scan asynchronously
            process = await asyncio.create_subprocess_exec(
                self.nmap_path,
                *nmap_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Wait for output with timeout
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(), 
                timeout=self.timeout
            )
            
            stdout_str = stdout_data.decode('utf-8', errors='replace')
            stderr_str = stderr_data.decode('utf-8', errors='replace')
            duration = time.time() - start_time

            # Check for Non-Zero Exit Code (Classic Failure)
            if process.returncode != 0:
                error_msg = stderr_str.strip() or stdout_str.strip() or "Unknown nmap error (non-zero exit)"
                return VisionScanResult(
                    success=False,
                    tool_name="nmap",
                    target=target,
                    scan_type=scan_type,
                    hosts=[],
                    error=error_msg,
                    command=command_str,
                    duration=duration
                )
            
            # Parse Valid XML Output
            parsed_data = VisionParser.parse_xml(stdout_str)
            hosts = parsed_data.get("hosts", [])

            # Check for "Silent Failure" signatures in text (DNS/Resolution errors)
            # Nmap often exits with code 0 even if it fails to resolve the target.
            combined_output = (stdout_str + stderr_str).lower()
            if "failed to resolve" in combined_output:
                 return VisionScanResult(
                    success=False,
                    tool_name="nmap",
                    target=target,
                    scan_type=scan_type,
                    hosts=[],
                    error=f"DNS Resolution Failed: Could not find '{target}'",
                    command=command_str,
                    duration=duration
                )

            # Success (Even if hosts is empty, it means the scan ran and found nothing)
            return VisionScanResult(
                success=True,
                tool_name="nmap",
                target=target,
                scan_type=scan_type,
                hosts=hosts,
                command=command_str,
                duration=duration
            )

        except asyncio.TimeoutError:
            if process:
                try:
                    process.kill()
                    await process.communicate()
                except ProcessLookupError:
                    pass
            
            return VisionScanResult(
                success=False,
                tool_name="nmap",
                target=target,
                scan_type=scan_type,
                hosts=[],
                error=f"Scan timed out after {self.timeout} seconds",
                duration=self.timeout
            )

        except asyncio.CancelledError:
            # Handle User Interrupt / Manual Stop
            if process:
                try:
                    process.kill()
                    await process.communicate()
                except ProcessLookupError:
                    pass
            
            return VisionScanResult(
                success=False,
                tool_name="nmap",
                target=target,
                scan_type=scan_type,
                hosts=[],
                error="Scan cancelled by user interrupt",
                duration=time.time() - start_time
            )

        except Exception as e:
            # Handle unexpected crashes
            if process:
                try:
                    process.kill()
                    await process.communicate()
                except:
                    pass

            return VisionScanResult(
                success=False,
                tool_name="nmap",
                target=target,
                scan_type=scan_type,
                hosts=[],
                error=f"Unexpected error: {str(e)}",
                duration=time.time() - start_time
            )