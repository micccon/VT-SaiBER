"""
Live striker integration test.

Runs inside the agents container, performs a real attackbox `recon_service_probe` through the
MCP bridge, normalizes the scan into `CyberState.discovered_targets`, and then
hands that state to the real unified striker worker.

By default the test stays safe and denies the approval gate before execution.
Set `LIVE_STRIKER_EXECUTE=true` to allow striker to proceed
past approval and attempt the exploit against the configured target.

Run inside the agents container:
    docker exec vt-saiber-agents python3 -m pytest tests/agent_tests/test_striker_live.py -q -s
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import src.agents.striker as em
from src.mcp.mcp_tool_bridge import get_mcp_bridge, reset_mcp_bridge
from src.utils.agent_parsers import extract_tool_output_text, parse_nmap_output, parse_service_records
from src.utils.parsers import normalize_tool_result


pytestmark = pytest.mark.live


LIVE_TARGET = (
    os.getenv("LIVE_STRIKER_TARGET")
    or os.getenv("LIVE_METASPLOIT_TARGET")
    or os.getenv("TARGET_HOST", "automotive-testbed")
).strip() or "automotive-testbed"
LIVE_NMAP_PORTS = (
    os.getenv("LIVE_STRIKER_PORTS")
    or os.getenv("LIVE_METASPLOIT_PORTS")
    or "21,22,80,443,8000,8080,9999"
).strip()
LIVE_NMAP_SCAN_TYPE = (
    os.getenv("LIVE_STRIKER_SCAN_TYPE")
    or os.getenv("LIVE_METASPLOIT_SCAN_TYPE")
    or "-sV"
).strip() or "-sV"
LIVE_NMAP_EXTRA_ARGS = (
    os.getenv("LIVE_STRIKER_EXTRA_ARGS")
    or os.getenv("LIVE_METASPLOIT_EXTRA_ARGS")
    or "-T4"
).strip()
LIVE_STRIKER_EXECUTE = (
    os.getenv("LIVE_STRIKER_EXECUTE")
    or os.getenv("LIVE_METASPLOIT_EXECUTE")
    or "false"
).strip().lower() == "true"


def _base_state(target: str) -> Dict[str, Any]:
    return {
        "mission_goal": f"Exploit the discovered services on {target} with striker",
        "mission_id": "test-striker-live",
        "mission_status": "active",
        "current_agent": "striker",
        "next_agent": None,
        "iteration_count": 0,
        "target_scope": [target],
        "discovered_targets": {},
        "ot_discovery": {},
        "web_findings": [],
        "active_sessions": {},
        "exploited_services": [],
        "research_cache": {},
        "intelligence_findings": [],
        "supervisor_messages": [],
        "supervisor_expectations": {},
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
        "credentials": {},
    }


async def _live_bridge_ready() -> bool:
    try:
        bridge = await get_mcp_bridge()
        exploit_tools = {tool.name for tool in bridge.get_tools_for_agent(em.STRIKER_ALLOWED_TOOLS)}
        scout_tools = {tool.name for tool in bridge.get_tools_for_agent({"recon_service_probe"})}
    except Exception:
        return False
    required = {
        "msf_search_modules",
        "msf_get_module_options",
        "msf_run_exploit",
        "msf_run_auxiliary",
        "msf_list_sessions",
    }
    return required.issubset(exploit_tools) and "recon_service_probe" in scout_tools


def _run(coro):
    async def _wrapped():
        try:
            return await coro
        finally:
            await reset_mcp_bridge()

    return asyncio.run(_wrapped())


async def _scan_target_into_state(target: str) -> tuple[Dict[str, Any], str]:
    bridge = await get_mcp_bridge()
    nmap_tool = next(
        (tool for tool in bridge.get_tools_for_agent({"recon_service_probe"}) if tool.name == "recon_service_probe"),
        None,
    )
    if nmap_tool is None:
        raise RuntimeError("Live attackbox recon_service_probe tool is unavailable")

    raw_scan = await nmap_tool.executor(
        target=target,
        ports=LIVE_NMAP_PORTS,
        additional_args=LIVE_NMAP_EXTRA_ARGS,
    )

    parsed = normalize_tool_result(raw_scan)
    service_records = ((parsed.get("evidence") or {}).get("services") or []) if isinstance(parsed, dict) else []
    services = parse_service_records(service_records) or parse_nmap_output(raw_scan)
    if not services:
        text = extract_tool_output_text(raw_scan) or str(raw_scan)
        raise RuntimeError(
            f"No open services were parsed from attackbox service probe output for {target}. Raw output:\n{text}"
        )

    state = _base_state(target)
    target_record = {
        "ip_address": target,
        "ports": sorted(services.keys()),
        "services": {
            str(port): service.model_dump() if hasattr(service, "model_dump") else service
            for port, service in services.items()
        },
    }
    state["discovered_targets"] = {target: target_record}

    for service in target_record["services"].values():
        version = str(service.get("version", "") or "").lower()
        banner = str(service.get("banner", "") or "").lower()
        if "vsftpd 2.3.4" in version or "vsftpd 2.3.4" in banner:
            state["intelligence_findings"] = [{"cve": "CVE-2011-2523"}]
            break

    return state, extract_tool_output_text(raw_scan) or str(raw_scan)


def test_striker_live_scans_into_cyberstate_then_runs_worker(monkeypatch):
    if not _run(_live_bridge_ready()):
        pytest.skip("Live attackbox MCP bridge or required tools are unavailable")

    try:
        state, raw_scan = _run(_scan_target_into_state(LIVE_TARGET))
    except RuntimeError as exc:
        pytest.skip(str(exc))

    # Default behavior stays safe; opt in to real execution with
    # LIVE_STRIKER_EXECUTE=true.
    monkeypatch.setattr(
        em,
        "require_manual_approval",
        lambda **kwargs: LIVE_STRIKER_EXECUTE,
    )

    result = _run(em.striker_node(state))

    assert result["current_agent"] == "striker"
    assert result["iteration_count"] == 1
    assert not result.get("errors"), result.get("errors")
    assert state["discovered_targets"][LIVE_TARGET]["services"], (
        f"nmap results were not persisted into CyberState for {LIVE_TARGET}.\n{raw_scan}"
    )
    assert "agent_log" in result and result["agent_log"], "agent_log should record the live attempt"

    log_entry = result["agent_log"][0]
    if hasattr(log_entry, "model_dump"):
        log_entry = log_entry.model_dump()

    findings = log_entry.get("findings") or {}
    assert findings or result.get("exploited_services"), "live run should produce findings or an execution record"

    observed_services = {
        str(service.get("service_name", "") or "").lower()
        for service in state["discovered_targets"][LIVE_TARGET]["services"].values()
        if isinstance(service, dict)
    }
    observed_versions = {
        str(service.get("version", "") or "").lower()
        for service in state["discovered_targets"][LIVE_TARGET]["services"].values()
        if isinstance(service, dict) and service.get("version")
    }

    search_terms = [str(term).lower() for term in findings.get("search_terms", [])]
    matched_terms = [str(term).lower() for term in findings.get("matched_terms", [])]
    reasoning = str(log_entry.get("reasoning") or "")
    reasoning_lower = reasoning.lower()
    assert (
        observed_services.intersection(search_terms)
        or observed_services.intersection(matched_terms)
        or observed_versions.intersection(search_terms)
        or any(service and service in reasoning_lower for service in observed_services)
        or any(version and version in reasoning_lower for version in observed_versions)
    ), "striker did not appear to consume the live nmap-derived CyberState evidence"

    assert "TARGET INTELLIGENCE:" in reasoning

    if LIVE_STRIKER_EXECUTE and result.get("exploited_services"):
        attempt = result["exploited_services"][0]
        if hasattr(attempt, "model_dump"):
            attempt = attempt.model_dump()
        assert attempt.get("module"), "live exploit attempt should record the chosen module"
    else:
        assert findings.get("status") in {"approval_blocked", "no_candidate"}
        if findings.get("status") == "approval_blocked":
            assert findings.get("module"), "live planning should select a module before the approval gate"
            assert "Execution blocked pending manual approval." in reasoning
        else:
            assert "No acceptable Metasploit module matched" in reasoning
