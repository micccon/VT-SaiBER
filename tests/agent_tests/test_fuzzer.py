#!/usr/bin/env python3
"""
Fuzzer Agent Tests
===================
Validates fuzzer target selection, gobuster output parsing, fallback behavior,
and web_findings state output.

Run inside agents container:
    docker exec vt-saiber-agents python tests/agent_tests/test_fuzzer.py
"""

import asyncio
import json
import sys
import traceback

sys.path.insert(0, "/app")

import src.agents.fuzzer as fuzzer_mod
from src.agents.fuzzer import FuzzerAgent, fuzzer_node
from src.main import build_initial_state
from langchain_core.tools import StructuredTool


class Results:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def add_pass(self, name):
        self.passed += 1
        print(f"  [PASS] {name}")

    def add_fail(self, name, err):
        self.failed += 1
        self.errors.append((name, err))
        print(f"  [FAIL] {name}: {err}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"Fuzzer Tests: {self.passed}/{total} passed")
        if self.errors:
            print("Failed:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print(f"{'='*60}")
        return self.failed == 0


results = Results()


class PatchContext:
    def __init__(self):
        self._saved = {}
    def set(self, obj, attr, value):
        self._saved[(obj, attr)] = getattr(obj, attr)
        setattr(obj, attr, value)
    def restore(self):
        for (obj, attr), val in reversed(list(self._saved.items())):
            setattr(obj, attr, val)
        self._saved.clear()


# ═══════════════════════════════════════════════════════════════
# TEST: Web target selection
# ═══════════════════════════════════════════════════════════════

def test_pick_web_target_http():
    agent = FuzzerAgent()
    targets = {
        "10.0.0.1": {
            "ports": [22, 80],
            "services": {
                "22": {"service_name": "ssh"},
                "80": {"service_name": "http", "version": "Apache 2.4"},
            },
        }
    }
    result = agent._pick_web_target(targets)
    if result is None:
        results.add_fail("test_pick_http", "Should find HTTP target")
        return
    if result["port"] != 80:
        results.add_fail("test_pick_http", f"Expected port 80, got {result['port']}")
        return
    results.add_pass("test_pick_http")


def test_pick_web_target_https():
    agent = FuzzerAgent()
    targets = {
        "10.0.0.1": {
            "ports": [443],
            "services": {"443": {"service_name": "https"}},
        }
    }
    result = agent._pick_web_target(targets)
    if result is None:
        results.add_fail("test_pick_https", "Should find HTTPS target")
        return
    if result["port"] != 443:
        results.add_fail("test_pick_https", f"Expected port 443, got {result['port']}")
        return
    results.add_pass("test_pick_https")


def test_pick_web_target_none():
    agent = FuzzerAgent()
    targets = {
        "10.0.0.1": {
            "ports": [22, 3306],
            "services": {
                "22": {"service_name": "ssh"},
                "3306": {"service_name": "mysql"},
            },
        }
    }
    result = agent._pick_web_target(targets)
    if result is not None:
        results.add_fail("test_pick_none", f"Should return None, got {result}")
        return
    results.add_pass("test_pick_none")


def test_pick_web_target_custom_port():
    agent = FuzzerAgent()
    targets = {
        "10.0.0.1": {
            "ports": [8000],
            "services": {"8000": {"service_name": "http", "version": "Python/3.8"}},
        }
    }
    result = agent._pick_web_target(targets)
    if result is None:
        results.add_fail("test_pick_custom_port", "Should find HTTP on 8000")
        return
    if result["port"] != 8000:
        results.add_fail("test_pick_custom_port", f"Expected 8000, got {result['port']}")
        return
    results.add_pass("test_pick_custom_port")


def test_pick_web_target_empty():
    agent = FuzzerAgent()
    result = agent._pick_web_target({})
    if result is not None:
        results.add_fail("test_pick_empty", "Should return None for empty targets")
        return
    results.add_pass("test_pick_empty")


# ═══════════════════════════════════════════════════════════════
# TEST: Gobuster output parsing
# ═══════════════════════════════════════════════════════════════

def test_parse_gobuster_standard():
    agent = FuzzerAgent()
    raw = json.dumps({
        "output": (
            "/admin (Status: 200) [Size: 1234]\n"
            "/login (Status: 301) [Size: 0]\n"
            "/api/v1 (Status: 200) [Size: 567]\n"
            "/health (Status: 200) [Size: 12]\n"
        )
    })
    findings = agent._parse_gobuster_output(raw, "http://10.0.0.1:8000")
    if len(findings) != 4:
        results.add_fail("test_parse_standard", f"Expected 4 findings, got {len(findings)}")
        return
    paths = [f["path"] for f in findings]
    if "/admin" not in paths or "/api/v1" not in paths:
        results.add_fail("test_parse_standard", f"Missing paths: {paths}")
        return
    api_finding = next(f for f in findings if f["path"] == "/api/v1")
    if not api_finding["is_api_endpoint"]:
        results.add_fail("test_parse_standard", "Should detect /api/v1 as API endpoint")
        return
    if "http://10.0.0.1:8000/admin" != findings[0]["url"]:
        results.add_fail("test_parse_standard", f"URL not constructed correctly: {findings[0]['url']}")
        return
    results.add_pass("test_parse_standard")


def test_parse_gobuster_empty():
    agent = FuzzerAgent()
    raw = json.dumps({"output": "No results found\n"})
    findings = agent._parse_gobuster_output(raw, "http://10.0.0.1")
    if findings:
        results.add_fail("test_parse_empty", f"Expected 0 findings, got {len(findings)}")
        return
    results.add_pass("test_parse_empty")


def test_parse_gobuster_nested_output():
    agent = FuzzerAgent()
    raw = json.dumps({
        "result": {"output": "/secret (Status: 403) [Size: 0]\n"}
    })
    findings = agent._parse_gobuster_output(raw, "http://10.0.0.1")
    if len(findings) != 1:
        results.add_fail("test_parse_nested", f"Expected 1, got {len(findings)}")
        return
    if findings[0]["status_code"] != 403:
        results.add_fail("test_parse_nested", f"Expected 403, got {findings[0]['status_code']}")
        return
    results.add_pass("test_parse_nested")


def test_parse_gobuster_raw_string():
    agent = FuzzerAgent()
    raw = "/backup (Status: 200) [Size: 9999]\n/test (Status: 404) [Size: 0]"
    findings = agent._parse_gobuster_output(raw, "http://10.0.0.1")
    if len(findings) != 2:
        results.add_fail("test_parse_raw_string", f"Expected 2, got {len(findings)}")
        return
    results.add_pass("test_parse_raw_string")


def test_parse_gobuster_max_100():
    agent = FuzzerAgent()
    lines = "\n".join(f"/path{i} (Status: 200) [Size: {i}]" for i in range(150))
    raw = json.dumps({"output": lines})
    findings = agent._parse_gobuster_output(raw, "http://10.0.0.1")
    if len(findings) > 100:
        results.add_fail("test_max_100", f"Should cap at 100, got {len(findings)}")
        return
    results.add_pass("test_max_100")


# ═══════════════════════════════════════════════════════════════
# TEST: Validation errors
# ═══════════════════════════════════════════════════════════════

async def test_fuzzer_no_http_target():
    state = build_initial_state("Test", ["10.0.0.1"], "fz-001")
    state["discovered_targets"] = {
        "10.0.0.1": {
            "ports": [22],
            "services": {"22": {"service_name": "ssh"}},
        }
    }
    out = await fuzzer_node(state)
    errs = out.get("errors", [])
    if not errs:
        results.add_fail("test_no_http", "Expected ValidationError")
        return
    err_type = getattr(errs[0], "error_type", errs[0].get("error_type", "") if isinstance(errs[0], dict) else "")
    if err_type != "ValidationError":
        results.add_fail("test_no_http", f"Expected ValidationError, got {err_type}")
        return
    results.add_pass("test_no_http")


async def test_fuzzer_no_targets():
    state = build_initial_state("Test", ["10.0.0.1"], "fz-002")
    state["discovered_targets"] = {}
    out = await fuzzer_node(state)
    errs = out.get("errors", [])
    if not errs:
        results.add_fail("test_no_targets", "Expected error")
        return
    results.add_pass("test_no_targets")


# ═══════════════════════════════════════════════════════════════
# TEST: MCP fallback
# ═══════════════════════════════════════════════════════════════

async def test_fuzzer_fallback_on_bridge_failure():
    """Fuzzer should return fallback finding when MCP unavailable."""
    patches = PatchContext()
    try:
        async def failing_bridge():
            raise ConnectionError("MCP down")

        patches.set(fuzzer_mod, "get_mcp_bridge", failing_bridge)
        state = build_initial_state("Test", ["10.0.0.1"], "fz-003")
        state["discovered_targets"] = {
            "10.0.0.1": {
                "ports": [80],
                "services": {"80": {"service_name": "http"}},
            }
        }
        out = await fuzzer_node(state)
        findings = out.get("web_findings", [])
        if not findings:
            results.add_fail("test_fuzzer_fallback", "Expected fallback finding")
            return
        if findings[0].get("path") != "/":
            results.add_fail("test_fuzzer_fallback", f"Expected / path, got {findings[0].get('path')}")
            return
        results.add_pass("test_fuzzer_fallback")
    except Exception as e:
        results.add_fail("test_fuzzer_fallback", str(e))
    finally:
        patches.restore()


async def test_fuzzer_success_with_mock():
    """Fuzzer with mocked gobuster produces correct findings."""
    patches = PatchContext()
    try:
        async def fake_gobuster(**kwargs):
            return json.dumps({
                "output": "/admin (Status: 200) [Size: 100]\n/api (Status: 301) [Size: 0]\n"
            })

        gobuster_tool = StructuredTool.from_function(
            func=lambda **kw: "{}",
            coroutine=fake_gobuster,
            name="kali_gobuster_scan",
            description="Mock gobuster",
        )

        class MockBridge:
            def get_tools_for_agent(self, allowed):
                return [gobuster_tool]

        async def mock_bridge():
            return MockBridge()

        patches.set(fuzzer_mod, "get_mcp_bridge", mock_bridge)
        state = build_initial_state("Test", ["10.0.0.1"], "fz-004")
        state["discovered_targets"] = {
            "10.0.0.1": {
                "ports": [80],
                "services": {"80": {"service_name": "http"}},
            }
        }
        out = await fuzzer_node(state)
        findings = out.get("web_findings", [])
        if len(findings) != 2:
            results.add_fail("test_fuzzer_mock", f"Expected 2 findings, got {len(findings)}")
            return
        paths = [f["path"] for f in findings]
        if "/admin" not in paths:
            results.add_fail("test_fuzzer_mock", f"Missing /admin: {paths}")
            return
        results.add_pass("test_fuzzer_mock")
    except Exception as e:
        traceback.print_exc()
        results.add_fail("test_fuzzer_mock", str(e))
    finally:
        patches.restore()


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

async def main():
    print("=" * 60)
    print("Fuzzer Agent Test Suite")
    print("=" * 60)

    # Target selection
    test_pick_web_target_http()
    test_pick_web_target_https()
    test_pick_web_target_none()
    test_pick_web_target_custom_port()
    test_pick_web_target_empty()

    # Gobuster parsing
    test_parse_gobuster_standard()
    test_parse_gobuster_empty()
    test_parse_gobuster_nested_output()
    test_parse_gobuster_raw_string()
    test_parse_gobuster_max_100()

    # Validation
    await test_fuzzer_no_http_target()
    await test_fuzzer_no_targets()

    # Fallback/MCP
    await test_fuzzer_fallback_on_bridge_failure()
    await test_fuzzer_success_with_mock()

    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
