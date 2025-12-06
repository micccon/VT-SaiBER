"""
Launch script for Stark HUD - VT-SaiBER Orchestrator Frontend

This script ensures all dependencies are available and starts the Streamlit app.
"""

import subprocess
import sys
import os
import time
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed."""
    try:
        import streamlit
        import yaml
        import httpx
        print("✅ All dependencies available")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please run: pip install -r requirements.txt")
        return False

def check_mcp_server():
    """Check if MCP server is running."""
    try:
        import httpx
        response = httpx.get("http://localhost:8000/health", timeout=2)
        if response.status_code == 200:
            print("✅ MCP server is running")
            return True
    except:
        # Fallback: check if port 8000 is open
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', 8000))
        sock.close()
        if result == 0:
            print("✅ MCP server port (8000) is open")
            return True
        pass
    
    print("⚠️  MCP server not detected on localhost:8000")
    print("Starting MCP server...")
    
    # Try to start MCP server
    try:
        server_path = Path(__file__).parent.parent.parent / "tools" / "vision" / "vision_mcp_server.py"
        if server_path.exists():
            # Set PYTHONPATH for the server process too
            env = os.environ.copy()
            env["PYTHONPATH"] = os.getcwd()
            
            subprocess.Popen([sys.executable, str(server_path)], env=env)
            time.sleep(3)  # Wait for server to start
            print("✅ MCP server started")
            return True
        else:
            print(f"❌ Cannot find MCP server script at {server_path}")
            return False
    except Exception as e:
        print(f"❌ Failed to start MCP server: {e}")
        return False

def main():
    """Launch the Stark HUD application."""
    print("🚀 Starting VT-SaiBER Stark HUD...")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check MCP server
    if not check_mcp_server():
        print("⚠️  Warning: MCP server may not be available")
        print("Make sure to start it manually: python tools/vision/vision_mcp_server.py")
    
    print("\n🌟 Launching Stark HUD...")
    print("Open your browser to the Streamlit URL when it appears")
    print("Press Ctrl+C to stop\n")
    
    # Set PYTHONPATH to current directory to ensure imports work
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    
    # Launch Streamlit
    subprocess.run([
        sys.executable, "-m", "streamlit", "run", 
        Path(__file__).parent / "stark_hud.py",
        "--server.headless", "true",
        "--theme.base", "dark"
    ], env=env)

if __name__ == "__main__":
    main()
