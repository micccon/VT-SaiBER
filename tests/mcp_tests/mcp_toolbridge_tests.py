"""
Attackbox MCP bridge tests.
"""

import asyncio
import json
import sys
import traceback

sys.path.insert(0, "/app")

from src.mcp.mcp_tool_bridge import get_mcp_bridge, reset_mcp_bridge


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def add_pass(self, test_name):
        self.passed += 1
        print(f"PASS: {test_name}")

    def add_fail(self, test_name, error):
        self.failed += 1
        self.errors.append((test_name, error))
        print(f"FAIL: {test_name}")
        print(f"  Error: {error}")

    def summary(self):
        total = self.passed + self.failed
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Total: {total}")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        if self.errors:
            print("\nFailed Tests:")
            for test_name, error in self.errors:
                print(f"  - {test_name}: {error}")
        print("=" * 60)
        return self.failed == 0


results = TestResults()


def _load_json(raw):
    if isinstance(raw, dict):
        return raw
    return json.loads(raw)


async def test_connect_attackbox():
    try:
        bridge = await get_mcp_bridge()
        if bridge.session is None:
            raise AssertionError("Attackbox session is not connected")
        if not bridge.all_tools:
            raise AssertionError("No attackbox tools discovered")
        results.add_pass("test_connect_attackbox")
        return bridge
    except Exception as e:
        results.add_fail("test_connect_attackbox", str(e))
        traceback.print_exc()
        return None


async def test_expected_tools_discovered():
    try:
        bridge = await get_mcp_bridge()
        tool_names = {tool.name for tool in bridge.all_tools}
        expected = {
            "recon_host_discovery",
            "recon_port_scan",
            "recon_service_probe",
            "web_content_enum",
            "web_nikto_scan",
            "web_http_request",
            "web_sqlmap_scan",
            "access_hydra_attack",
            "access_john_crack",
            "access_ssh_login",
            "msf_search_modules",
            "msf_get_module_options",
            "msf_run_exploit",
            "msf_run_auxiliary",
            "msf_run_post",
            "msf_list_sessions",
            "msf_session_command",
            "msf_start_listener",
            "msf_terminate_session",
            "system_execute_command",
        }
        missing = sorted(expected - tool_names)
        if missing:
            raise AssertionError(f"Missing expected tools: {missing}")
        results.add_pass("test_expected_tools_discovered")
    except Exception as e:
        results.add_fail("test_expected_tools_discovered", str(e))
        traceback.print_exc()


async def test_normalized_envelope_for_command():
    try:
        bridge = await get_mcp_bridge()
        tool = next((tool for tool in bridge.all_tools if tool.name == "system_execute_command"), None)
        if tool is None:
            raise AssertionError("system_execute_command not found")

        result = _load_json(await tool.coroutine(command="echo MCP_TEST_SUCCESS"))
        required = {"status", "summary", "evidence", "artifacts", "raw", "metadata", "validation"}
        missing = required - set(result)
        if missing:
            raise AssertionError(f"Envelope missing keys: {sorted(missing)}")
        if result["status"] != "success":
            raise AssertionError(f"Expected success status, got: {result}")
        if result["validation"].get("outcome") != "inconclusive":
            raise AssertionError(f"Expected inconclusive validation, got: {result['validation']}")
        if "MCP_TEST_SUCCESS" not in str(result["raw"].get("stdout", "")):
            raise AssertionError(f"Command output missing marker: {result}")
        results.add_pass("test_normalized_envelope_for_command")
    except Exception as e:
        results.add_fail("test_normalized_envelope_for_command", str(e))
        traceback.print_exc()


async def test_recon_port_scan_localhost():
    try:
        bridge = await get_mcp_bridge()
        tool = next((tool for tool in bridge.all_tools if tool.name == "recon_port_scan"), None)
        if tool is None:
            raise AssertionError("recon_port_scan not found")

        result = _load_json(await tool.coroutine(target="127.0.0.1", ports="22,80,443", additional_args="-T4"))
        if result["status"] not in {"success", "error"}:
            raise AssertionError(f"Unexpected status: {result['status']}")
        if "raw" not in result:
            raise AssertionError(f"Missing raw field: {result}")
        results.add_pass("test_recon_port_scan_localhost")
    except Exception as e:
        results.add_fail("test_recon_port_scan_localhost", str(e))
        traceback.print_exc()


async def test_allowlist_filtering():
    try:
        bridge = await get_mcp_bridge()
        scout_tools = bridge.get_tools_for_agent({"recon_host_discovery", "recon_port_scan", "recon_service_probe"})
        scout_names = {tool.name for tool in scout_tools}
        if "recon_port_scan" not in scout_names:
            raise AssertionError(f"Scout missing recon_port_scan: {sorted(scout_names)}")
        if "msf_run_exploit" in scout_names:
            raise AssertionError("Scout should not receive msf_run_exploit")
        results.add_pass("test_allowlist_filtering")
    except Exception as e:
        results.add_fail("test_allowlist_filtering", str(e))
        traceback.print_exc()


async def test_bridge_reset_is_safe():
    try:
        bridge = await get_mcp_bridge()
        if bridge.session is None:
            raise AssertionError("Bridge must be connected before reset")
        await reset_mcp_bridge()
        await reset_mcp_bridge()
        fresh_bridge = await get_mcp_bridge()
        if fresh_bridge.session is None:
            raise AssertionError("Bridge should reconnect after reset")
        results.add_pass("test_bridge_reset_is_safe")
    except Exception as e:
        results.add_fail("test_bridge_reset_is_safe", str(e))
        traceback.print_exc()


async def run_all_tests():
    print("\n" + "=" * 60)
    print("ATTACKBOX MCP BRIDGE TEST SUITE")
    print("=" * 60)

    bridge = await test_connect_attackbox()
    if not bridge:
        results.summary()
        return 1

    await test_expected_tools_discovered()
    await test_normalized_envelope_for_command()
    await test_recon_port_scan_localhost()
    await test_allowlist_filtering()
    await test_bridge_reset_is_safe()

    success = results.summary()
    await reset_mcp_bridge()
    return 0 if success else 1


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(run_all_tests()))
    except KeyboardInterrupt:
        print("\nTests interrupted by user")
        raise SystemExit(1)
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        traceback.print_exc()
        raise SystemExit(1)
