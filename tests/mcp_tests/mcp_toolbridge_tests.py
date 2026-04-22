"""
MCP Bridge Tests - SSE Architecture
===================================
Tests all tools from Kali and MSF MCP servers.
Both use SSE transport now.
"""

import asyncio
import sys
sys.path.insert(0, '/app')

import traceback
from src.mcp.mcp_tool_bridge import get_mcp_bridge


class TestResults:
    """Track test results."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
    
    def add_pass(self, test_name):
        self.passed += 1
        print(f"✅ PASS: {test_name}")
    
    def add_fail(self, test_name, error):
        self.failed += 1
        self.errors.append((test_name, error))
        print(f"❌ FAIL: {test_name}")
        print(f"   Error: {error}")
    
    def summary(self):
        total = self.passed + self.failed
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        print(f"Total: {total}")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        
        if self.errors:
            print("\nFailed Tests:")
            for test_name, error in self.errors:
                print(f"  - {test_name}: {error}")
        
        print("="*60)
        return self.failed == 0


results = TestResults()


# =============================================================================
# Connection Tests
# =============================================================================

async def test_connect_both_servers():
    """Test connecting to both Kali and MSF via SSE."""
    try:
        bridge = await get_mcp_bridge()
        
        # Check both servers connected
        if "kali" not in bridge.sessions or "msf" not in bridge.sessions:
            raise AssertionError("Not all servers connected")
        
        # Check tools discovered
        if len(bridge.all_tools) == 0:
            raise AssertionError("No tools discovered")
        
        kali_count = len(bridge.tools_by_server.get("kali", []))
        msf_count = len(bridge.tools_by_server.get("msf", []))
        
        print(f"   Kali tools: {kali_count}")
        print(f"   MSF tools: {msf_count}")
        print(f"   Total: {len(bridge.all_tools)}")
        
        results.add_pass("test_connect_both_servers")
        return bridge
        
    except Exception as e:
        results.add_fail("test_connect_both_servers", str(e))
        traceback.print_exc()
        return None


# =============================================================================
# Tool Discovery Tests
# =============================================================================

async def test_kali_tools_discovered():
    """Test that expected Kali tools are present."""
    try:
        bridge = await get_mcp_bridge()
        
        tool_names = [t.name.lower() for t in bridge.all_tools]
        
        # Expected tools from Kali MCP server
        # These match the @mcp.tool decorators in mcp_server.py
        expected = [
            "nmap_scan",
            "gobuster_scan", 
            "nikto_scan",
            "sqlmap_scan",
            "hydra_attack",
            "execute_command"
        ]
        
        missing = []
        for tool in expected:
            # Check with kali_ prefix
            if not any(f"kali_{tool}" in name for name in tool_names):
                missing.append(tool)
        
        if missing:
            print(f"   Available tools: {tool_names}")
            raise AssertionError(f"Missing Kali tools: {missing}")
        
        results.add_pass("test_kali_tools_discovered")
        
    except Exception as e:
        results.add_fail("test_kali_tools_discovered", str(e))
        traceback.print_exc()


async def test_msf_tools_discovered():
    """Test that expected MSF tools are present."""
    try:
        bridge = await get_mcp_bridge()
        
        tool_names = [t.name.lower() for t in bridge.all_tools]
        
        # Expected tools from MetasploitMCP
        expected = [
            "list_exploits",
            "list_payloads",
            "run_exploit",
            "list_active_sessions",
            "start_listener"
        ]
        
        missing = []
        for tool in expected:
            # Check with msf_ prefix
            if not any(f"msf_{tool}" in name for name in tool_names):
                missing.append(tool)
        
        if missing:
            print(f"   Available tools: {tool_names}")
            raise AssertionError(f"Missing MSF tools: {missing}")
        
        results.add_pass("test_msf_tools_discovered")
        
    except Exception as e:
        results.add_fail("test_msf_tools_discovered", str(e))
        traceback.print_exc()


# =============================================================================
# Kali Tool Execution Tests
# =============================================================================

async def test_kali_execute_command():
    """Test executing a safe command via Kali."""
    try:
        bridge = await get_mcp_bridge()
        
        # Find execute_command tool
        exec_tool = None
        for tool in bridge.all_tools:
            if "execute_command" in tool.name.lower():
                exec_tool = tool
                break
        
        if not exec_tool:
            raise AssertionError("execute_command tool not found")
        
        # Execute safe command
        result = await exec_tool.coroutine(command="echo 'MCP_TEST_SUCCESS'")
        
        if not result or "MCP_TEST_SUCCESS" not in result:
            raise AssertionError(f"Unexpected result: {result}")
        
        print(f"   Output: {result[:200]}")
        results.add_pass("test_kali_execute_command")
        
    except Exception as e:
        results.add_fail("test_kali_execute_command", str(e))
        traceback.print_exc()


async def test_kali_nmap_localhost():
    """Test nmap ping scan on localhost (safe and fast)."""
    try:
        bridge = await get_mcp_bridge()
        
        # Find nmap tool
        nmap_tool = None
        for tool in bridge.all_tools:
            if "nmap_scan" in tool.name.lower():
                nmap_tool = tool
                break
        
        if not nmap_tool:
            raise AssertionError("nmap_scan tool not found")
        
        # Execute lightweight ping scan
        result = await nmap_tool.coroutine(
            target="127.0.0.1",
            scan_type="-sn",  # Ping scan only
            additional_args="-T4"
        )
        
        if not result or len(result) == 0:
            raise AssertionError("Empty result from nmap")
        
        # Check for success indicators
        if "error" in result.lower() and "Host is up" not in result:
            raise AssertionError(f"nmap failed: {result}")
        
        print(f"   Output: {result[:500]}")
        results.add_pass("test_kali_nmap_localhost")
        
    except Exception as e:
        results.add_fail("test_kali_nmap_localhost", str(e))
        traceback.print_exc()


async def test_kali_gobuster_version():
    """Test gobuster by checking its version (no actual scan)."""
    try:
        bridge = await get_mcp_bridge()
        
        # Find execute_command to run gobuster --version
        exec_tool = None
        for tool in bridge.all_tools:
            if "execute_command" in tool.name.lower():
                exec_tool = tool
                break
        
        if not exec_tool:
            raise AssertionError("execute_command tool not found")
        
        result = await exec_tool.coroutine(command="gobuster version")
        
        if not result or "error" in result.lower():
            raise AssertionError(f"gobuster not working: {result}")
        
        print(f"   Output: {result[:200]}")
        results.add_pass("test_kali_gobuster_version")
        
    except Exception as e:
        results.add_fail("test_kali_gobuster_version", str(e))
        traceback.print_exc()


async def test_kali_nikto_version():
    """Test nikto by checking its version."""
    try:
        bridge = await get_mcp_bridge()
        
        exec_tool = None
        for tool in bridge.all_tools:
            if "execute_command" in tool.name.lower():
                exec_tool = tool
                break
        
        if not exec_tool:
            raise AssertionError("execute_command tool not found")
        
        result = await exec_tool.coroutine(command="nikto -Version")
        
        if not result or ("nikto" not in result.lower() and "error" in result.lower()):
            raise AssertionError(f"nikto not working: {result}")
        
        print(f"   Output: {result[:200]}")
        results.add_pass("test_kali_nikto_version")
        
    except Exception as e:
        results.add_fail("test_kali_nikto_version", str(e))
        traceback.print_exc()


# =============================================================================
# MSF Tool Execution Tests
# =============================================================================

async def test_msf_list_exploits():
    """Test listing exploits from Metasploit."""
    try:
        bridge = await get_mcp_bridge()
        
        # Find list_exploits tool
        list_tool = None
        for tool in bridge.all_tools:
            if "list_exploits" in tool.name.lower():
                list_tool = tool
                break
        
        if not list_tool:
            raise AssertionError("list_exploits tool not found")
        
        # Search for common exploits
        # list_exploits uses search_term= (not query=) — wrong param silently returns all
        result = await list_tool.coroutine(search_term="ms17")
        
        if not result:
            raise AssertionError("Empty result from list_exploits")
        
        # Check if it's valid JSON response
        if "error" in result.lower() and "results" not in result.lower():
            raise AssertionError(f"list_exploits failed: {result}")
        
        print(f"   Output: {result[:500]}")
        results.add_pass("test_msf_list_exploits")
        
    except Exception as e:
        results.add_fail("test_msf_list_exploits", str(e))
        traceback.print_exc()


async def test_msf_list_payloads():
    """Test listing payloads from Metasploit."""
    try:
        bridge = await get_mcp_bridge()
        
        # Find list_payloads tool
        list_tool = None
        for tool in bridge.all_tools:
            if "list_payloads" in tool.name.lower():
                list_tool = tool
                break
        
        if not list_tool:
            raise AssertionError("list_payloads tool not found")
        
        # List Linux x64 payloads
        result = await list_tool.coroutine(platform="linux", arch="x64")
        
        if not result:
            raise AssertionError("Empty result from list_payloads")
        
        if "error" in result.lower() and "payload" not in result.lower():
            raise AssertionError(f"list_payloads failed: {result}")
        
        print(f"   Output: {result[:500]}")
        results.add_pass("test_msf_list_payloads")
        
    except Exception as e:
        results.add_fail("test_msf_list_payloads", str(e))
        traceback.print_exc()


async def test_msf_list_sessions():
    """Test listing Metasploit sessions (should be empty)."""
    try:
        bridge = await get_mcp_bridge()
        
        # Find list_sessions tool
        list_tool = None
        for tool in bridge.all_tools:
            if "list_active_sessions" in tool.name.lower() or "list_sessions" in tool.name.lower():
                list_tool = tool
                break
        
        if not list_tool:
            raise AssertionError("list_sessions tool not found")
        
        # List sessions (should return empty list or valid response)
        result = await list_tool.coroutine()
        
        if result is None:
            raise AssertionError("None result from list_sessions")
        
        # Even empty is OK - just check it doesn't error
        if "error" in result.lower() and "session" not in result.lower():
            raise AssertionError(f"list_sessions failed: {result}")
        
        print(f"   Output: {result[:500]}")
        results.add_pass("test_msf_list_sessions")
        
    except Exception as e:
        results.add_fail("test_msf_list_sessions", str(e))
        traceback.print_exc()

# =============================================================================
# Tool Filtering Tests
# =============================================================================

async def test_tool_filtering_scout():
    """Test filtering tools for Scout agent."""
    try:
        bridge = await get_mcp_bridge()
        
        # Scout should only get recon tools
        scout_allowed = {"nmap_scan", "execute_command", "server_health"}
        scout_tools = bridge.get_tools_for_agent(scout_allowed)
        
        scout_names = [t.name for t in scout_tools]
        
        # Verify scout has nmap
        if not any("nmap_scan" in name for name in scout_names):
            raise AssertionError(f"Scout missing nmap_scan. Has: {scout_names}")
        
        # Verify scout doesn't have exploits
        if any("run_exploit" in name for name in scout_names):
            raise AssertionError("Scout has run_exploit (should not)")
        
        print(f"   Scout tools: {scout_names}")
        results.add_pass("test_tool_filtering_scout")
        
    except Exception as e:
        results.add_fail("test_tool_filtering_scout", str(e))
        traceback.print_exc()


async def test_tool_filtering_striker():
    """Test filtering tools for Striker agent."""
    try:
        bridge = await get_mcp_bridge()
        
        # Striker should only get exploit tools
        striker_allowed = {"run_exploit", "list_exploits", "list_payloads", "list_active_sessions"}
        striker_tools = bridge.get_tools_for_agent(striker_allowed)
        
        striker_names = [t.name for t in striker_tools]
        
        # Verify striker has exploits
        if not any("list_exploits" in name for name in striker_names):
            raise AssertionError(f"Striker missing list_exploits. Has: {striker_names}")
        
        # Verify striker doesn't have nmap
        if any("nmap_scan" in name for name in striker_names):
            raise AssertionError("Striker has nmap_scan (should not)")
        
        print(f"   Striker tools: {striker_names}")
        results.add_pass("test_tool_filtering_striker")
        
    except Exception as e:
        results.add_fail("test_tool_filtering_striker", str(e))
        traceback.print_exc()


async def test_none_filter_returns_empty():
    """Test that None allowlist returns no tools (deny by default)."""
    try:
        bridge = await get_mcp_bridge()

        no_tools = bridge.get_tools_for_agent(None)

        if len(no_tools) != 0:
            raise AssertionError(
                f"None allowlist should return 0 tools (deny by default). "
                f"Got {len(no_tools)}: {[t.name for t in no_tools]}"
            )

        print(f"   None filter correctly returned 0 tools (total available: {len(bridge.all_tools)})")
        results.add_pass("test_none_filter_returns_empty")

    except Exception as e:
        results.add_fail("test_none_filter_returns_empty", str(e))
        traceback.print_exc()


# =============================================================================
# Main Test Runner
# =============================================================================

async def run_all_tests():
    """Run all tests."""
    
    print("\n" + "="*60)
    print("MCP BRIDGE TEST SUITE (SSE Architecture)")
    print("="*60)
    
    # Connection tests
    print("\n--- CONNECTION TESTS ---")
    bridge = await test_connect_both_servers()
    
    if not bridge:
        print("❌ Failed to connect to servers. Aborting remaining tests.")
        results.summary()
        return 1
    
    # Tool discovery tests
    print("\n--- TOOL DISCOVERY TESTS ---")
    await test_kali_tools_discovered()
    await test_msf_tools_discovered()
    
    # Kali tool execution tests
    print("\n--- KALI TOOL EXECUTION TESTS ---")
    await test_kali_execute_command()
    await test_kali_nmap_localhost()
    await test_kali_gobuster_version()
    await test_kali_nikto_version()
    
    # MSF tool execution tests
    print("\n--- MSF TOOL EXECUTION TESTS ---")
    await test_msf_list_exploits()
    await test_msf_list_payloads()
    await test_msf_list_sessions()
    
    # Tool filtering tests
    print("\n--- TOOL FILTERING TESTS ---")
    await test_tool_filtering_scout()
    await test_tool_filtering_striker()
    await test_none_filter_returns_empty()
    
    # Print summary
    success = results.summary()
    
    # Print discovered tools
    kali_tools = bridge.tools_by_server.get("kali", [])
    msf_tools = bridge.tools_by_server.get("msf", [])
    
    if kali_tools:
        print(f"\n📋 Kali Tools ({len(kali_tools)}):")
        for tool in kali_tools[:5]:
            print(f"   - {tool.name}")
        if len(kali_tools) > 5:
            print(f"   ... and {len(kali_tools) - 5} more")
    
    if msf_tools:
        print(f"\n📋 MSF Tools ({len(msf_tools)}):")
        for tool in msf_tools[:5]:
            print(f"   - {tool.name}")
        if len(msf_tools) > 5:
            print(f"   ... and {len(msf_tools) - 5} more")
    
    # Cleanup
    await bridge.disconnect()
    
    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(run_all_tests())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n❌ Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ FATAL ERROR: {e}")
        traceback.print_exc()
        sys.exit(1)