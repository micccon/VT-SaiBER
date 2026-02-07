#!/usr/bin/env python3
"""
MSF MCP Client Test
===================
Tests the MSF MCP client via MCP protocol (not REST).
"""
import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, '/app')

from src.mcp.msf_mcp_client import MsfMCPClient


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
    """Run all MSF MCP tests."""
    print("="*60)
    print("🧪 MSF MCP CLIENT TESTS")
    print("="*60)
    
    results = []
    msf = MsfMCPClient()
    
    # Test 1: Connection
    results.append(await test(
        "Connect to MSF MCP",
        msf.connect()
    ))
    
    # Test 2: List tools
    results.append(await test(
        "List available tools",
        msf.list_tools()
    ))
    
    # Test 3: Search exploits
    results.append(await test(
        "list_exploits: Search for vsftpd",
        msf.call("list_exploits", {
            "search_term": "vsftpd"
        })
    ))
    
    # Test 4: List payloads
    results.append(await test(
        "list_payloads: Linux x64",
        msf.call("list_payloads", {
            "platform": "linux",
            "arch": "x64"
        })
    ))
    
    # Test 5: List sessions
    results.append(await test(
        "list_active_sessions",
        msf.call("list_active_sessions", {})
    ))
    
    # # Test 6: Health check
    # results.append(await test(
    #     "Health check",
    #     msf.health_check()
    # ))
    
    # Cleanup
    await msf.disconnect()
    
    # Summary
    print(f"\n{'='*60}")
    print(f"Passed: {sum(results)}/{len(results)}")
    print(f"{'='*60}")
    
    return 0 if all(results) else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)