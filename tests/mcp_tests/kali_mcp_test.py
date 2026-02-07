#!/usr/bin/env python3
"""
Kali MCP Client Test
====================
Tests the Kali MCP client via MCP protocol (not REST).
"""
import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, '/app')

from src.mcp.kali_mcp_client import KaliMCPClient


async def test(name, coro):
    """Run a test coroutine."""
    print(f"\n{'='*60}\n{name}\n{'='*60}")
    try:
        result = await coro
        print(f"✅ PASS")
        print(f"Result: {str(result)[:300]}")
        return True
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False


async def main():
    """Run all Kali MCP tests."""
    print("="*60)
    print("🧪 KALI MCP CLIENT TESTS")
    print("="*60)
    
    results = []
    kali = KaliMCPClient()
    
    # Test 1: Connection
    results.append(await test(
        "Connect to Kali MCP",
        kali.connect()
    ))
    
    # Test 2: List tools
    results.append(await test(
        "List available tools",
        kali.list_tools()
    ))
    
    # Test 3: nmap tool (ping scan)
    results.append(await test(
        "nmap: Ping scan 8.8.8.8",
        kali.call("nmap", {
            "target": "8.8.8.8",
            "scan_type": "-sn",
            "ports": "",
            "additional_args": ""
        })
    ))
    
    # Test 4: execute_command
    results.append(await test(
        "execute_command: whoami",
        kali.call("execute_command", {
            "command": "whoami"
        })
    ))
    
    # # Test 5: Health check
    # results.append(await test(
    #     "Health check",
    #     kali.health_check()
    # ))
    
    # Cleanup
    await kali.disconnect()
    
    # Summary
    print(f"\n{'='*60}")
    print(f"Passed: {sum(results)}/{len(results)}")
    print(f"{'='*60}")
    
    return 0 if all(results) else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)