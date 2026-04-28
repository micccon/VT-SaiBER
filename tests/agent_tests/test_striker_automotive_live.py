"""
Live striker-only automotive integration test.

Runs inside the agents container, performs a real attackbox `recon_service_probe`, executes
real web fuzzing tools directly through the MCP bridge, persists those findings
into the operational database, queries the database and RAG layer using the
fresh evidence, and then invokes only the striker worker.

This intentionally avoids supervisor, librarian, and fuzzer agent runs to keep
token use focused on striker itself.

Run inside the agents container:
    python3 -m pytest tests/agent_tests/test_striker_automotive_live.py -q -s

Use `LIVE_STRIKER_EXECUTE=true` to allow the striker worker to attempt live
Metasploit execution. Otherwise the approval gate is denied for a planning-only
test.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import src.agents.striker as striker_module
from src.agents.fuzzer import FUZZER_ALLOWED_TOOLS, FuzzerAgent
from src.database.manager import get_target_info
from src.database.persistence import persist_state_update
from src.mcp.mcp_tool_bridge import get_mcp_bridge, reset_mcp_bridge
from src.state.cyber_state import CyberState
from src.utils.agent_parsers import (
    dedupe_web_findings,
    extract_tool_output_text,
    parse_gobuster_output,
    parse_nikto_output,
    parse_nmap_output,
    parse_service_records,
)
from src.utils.tools import RuntimeTool


pytestmark = pytest.mark.live


LIVE_TARGET = (
    os.getenv("LIVE_STRIKER_TARGET")
    or os.getenv("LIVE_METASPLOIT_TARGET")
    or os.getenv("TARGET_HOST")
    or "automotive-testbed"
).strip() or "automotive-testbed"
LIVE_NMAP_PORTS = (
    os.getenv("LIVE_STRIKER_PORTS")
    or os.getenv("LIVE_METASPLOIT_PORTS")
    or "22,80,443,8000,8080,9555,9556,9999"
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
LIVE_KB_TOP_K = int((os.getenv("LIVE_STRIKER_KB_TOP_K") or "5").strip() or "5")
TRACE_EVENTS: List[Dict[str, Any]] = []


def _step(message: str) -> None:
    print(f"[STEP] {message}", flush=True)


def _trace(label: str, payload: Dict[str, Any]) -> None:
    print(f"[TRACE] {label}: {json.dumps(_safe_json(payload), default=str)}", flush=True)


def _result_preview(value: Any, max_chars: int = 6000) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(_safe_json(value), default=str, indent=2)
    return text[:max_chars] + ("...(truncated)" if len(text) > max_chars else "")


def _mission_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"striker-automotive-live-{stamp}"


def _run(coro):
    async def _wrapped():
        try:
            return await coro
        finally:
            await reset_mcp_bridge()

    return asyncio.run(_wrapped())


def _base_state(target: str, mission_id: str) -> CyberState:
    return {
        "mission_goal": f"Exploit the discovered services on {target} with striker",
        "mission_id": mission_id,
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
    }


def _safe_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _safe_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if hasattr(value, "model_dump"):
        return _safe_json(value.model_dump())
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass
    return value


def _wrap_tool_with_trace(tool: RuntimeTool) -> RuntimeTool:
    async def traced_coroutine(**kwargs):
        call_id = len(TRACE_EVENTS) + 1
        event = {
            "id": call_id,
            "tool": tool.name,
            "args": kwargs,
            "status": "started",
        }
        TRACE_EVENTS.append(event)
        _trace("TOOL_START", {"id": call_id, "tool": tool.name, "args": kwargs})
        started = asyncio.get_running_loop().time()
        try:
            result = await tool.executor(**kwargs)

            elapsed = asyncio.get_running_loop().time() - started
            event["status"] = "ok"
            event["elapsed_s"] = round(elapsed, 3)
            event["result_preview"] = _result_preview(result)
            _trace(
                "TOOL_END",
                {
                    "id": call_id,
                    "tool": tool.name,
                    "status": "ok",
                    "elapsed_s": round(elapsed, 3),
                },
            )
            print(f"[TRACE] TOOL_RESULT[{call_id}]:\n{_result_preview(result)}", flush=True)
            return result
        except Exception as exc:
            elapsed = asyncio.get_running_loop().time() - started
            event["status"] = "error"
            event["elapsed_s"] = round(elapsed, 3)
            event["error"] = str(exc)
            _trace(
                "TOOL_END",
                {
                    "id": call_id,
                    "tool": tool.name,
                    "status": "error",
                    "elapsed_s": round(elapsed, 3),
                    "error": str(exc),
                },
            )
            raise

    return RuntimeTool(
        name=tool.name,
        description=tool.description,
        input_schema=tool.input_schema,
        executor=traced_coroutine,
        defaults=tool.defaults,
    )


async def _enable_tool_tracing() -> Any:
    _step("Enabling traced MCP tool wrappers")
    bridge = await get_mcp_bridge()
    original_get_tools = bridge.get_tools_for_agent

    def traced_get_tools(allowed_tools=None):
        tools = original_get_tools(allowed_tools)
        return [_wrap_tool_with_trace(tool) for tool in tools]

    bridge.get_tools_for_agent = traced_get_tools
    return bridge, original_get_tools


async def _bridge_tools_for_suffixes(suffixes: set[str]) -> Dict[str, Any]:
    _step(f"Connecting to MCP bridge for tools: {sorted(suffixes)}")
    bridge = await get_mcp_bridge()
    tools: Dict[str, Any] = {}
    for tool in bridge.get_tools_for_agent(suffixes):
        for suffix in suffixes:
            if tool.name.endswith(suffix):
                tools[suffix] = tool
                break
    _step(f"Resolved MCP tools: {sorted(tools)}")
    return tools


async def _live_prereqs_ready() -> bool:
    try:
        _step("Checking live MCP prerequisites")
        _step("Calling get_mcp_bridge() for prereq check")
        bridge = await get_mcp_bridge()
        _step("MCP bridge acquired for prereq check")
        _step("Filtering striker tools for prereq check")
        striker_tools = {tool.name for tool in bridge.get_tools_for_agent(striker_module.STRIKER_ALLOWED_TOOLS)}
        _step(f"Striker tool count: {len(striker_tools)}")
        _step("Filtering scout tools for prereq check")
        scout_tools = {tool.name for tool in bridge.get_tools_for_agent({"recon_service_probe"})}
        _step(f"Scout tool count: {len(scout_tools)}")
        _step("Filtering fuzzer tools for prereq check")
        fuzz_tools = {tool.name for tool in bridge.get_tools_for_agent(FUZZER_ALLOWED_TOOLS)}
        _step(f"Fuzzer tool count: {len(fuzz_tools)}")
    except Exception:
        return False

    required_striker = {
        "msf_search_modules",
        "msf_get_module_options",
        "msf_run_exploit",
        "msf_run_auxiliary",
        "msf_list_sessions",
    }
    has_nmap = "recon_service_probe" in scout_tools
    has_fuzzer = ("web_content_enum" in fuzz_tools) or ("web_nikto_scan" in fuzz_tools)
    return required_striker.issubset(striker_tools) and has_nmap and has_fuzzer


async def _scan_target_into_state(
    target: str,
    mission_id: str,
) -> Tuple[CyberState, str]:
    _step(f"Starting attackbox service probe for {target}")
    tools = await _bridge_tools_for_suffixes({"recon_service_probe"})
    nmap_tool = tools.get("recon_service_probe")
    if nmap_tool is None:
        raise RuntimeError("Live attackbox recon_service_probe tool is unavailable")

    raw_scan = await nmap_tool.executor(
        target=target,
        ports=LIVE_NMAP_PORTS,
        additional_args=LIVE_NMAP_EXTRA_ARGS,
    )
    _step("Finished attackbox service probe; parsing discovered services")

    parsed = json.loads(raw_scan) if isinstance(raw_scan, str) else raw_scan
    service_records = (((parsed or {}).get("evidence") or {}).get("services") or []) if isinstance(parsed, dict) else []
    services = parse_service_records(service_records) or parse_nmap_output(raw_scan)
    if not services:
        text = extract_tool_output_text(raw_scan) or str(raw_scan)
        raise RuntimeError(f"No open services were parsed from attackbox service probe output for {target}.\n{text}")

    state = _base_state(target, mission_id)
    state["discovered_targets"] = {
        target: {
            "ip_address": target,
            "ports": sorted(services.keys()),
            "services": {
                str(port): service.model_dump() if hasattr(service, "model_dump") else service
                for port, service in services.items()
            },
        }
    }
    _step(f"Built discovered_targets with ports: {state['discovered_targets'][target]['ports']}")
    return state, extract_tool_output_text(raw_scan) or str(raw_scan)


def _pick_web_base_url(discovered_targets: Dict[str, Dict[str, Any]]) -> Optional[str]:
    fuzzer = FuzzerAgent()
    target = fuzzer._pick_web_target(discovered_targets)
    if target is None:
        return None

    ip = target["ip"]
    port = int(target["port"])
    scheme = "https" if port == 443 else "http"
    if port in {80, 443}:
        return f"{scheme}://{ip}"
    return f"{scheme}://{ip}:{port}"


async def _collect_web_findings(discovered_targets: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    base_url = _pick_web_base_url(discovered_targets)
    if not base_url:
        _step("No HTTP target found for fuzzing; skipping web enumeration")
        return {"base_url": None, "findings": [], "raw": {}}

    _step(f"Starting web fuzzing against {base_url}")
    fuzzer = FuzzerAgent()
    tools = await _bridge_tools_for_suffixes(FUZZER_ALLOWED_TOOLS)
    findings: List[Dict[str, Any]] = []
    raw: Dict[str, str] = {}

    gobuster_tool = tools.get("web_content_enum")
    if gobuster_tool is not None:
        _step("Calling attackbox web_content_enum")
        gobuster_raw = await gobuster_tool.executor(
            url=base_url,
            wordlist="/usr/share/wordlists/dirb/common.txt",
            additional_args="--delay 200ms",
        )
        raw["web_content_enum"] = extract_tool_output_text(gobuster_raw)
        findings.extend(
            parse_gobuster_output(
                gobuster_raw,
                base_url=base_url,
                max_depth=3,
                soft_404_statuses={404},
                scan_policy=fuzzer._scan_policy(),
            )
        )

    nikto_tool = tools.get("web_nikto_scan")
    if nikto_tool is not None:
        _step("Calling attackbox web_nikto_scan")
        nikto_raw = await nikto_tool.executor(target=base_url, additional_args="")
        raw["web_nikto_scan"] = extract_tool_output_text(nikto_raw)
        findings.extend(
            parse_nikto_output(
                nikto_raw,
                base_url=base_url,
                max_depth=3,
                scan_policy=fuzzer._scan_policy(),
            )
        )

    return {
        "base_url": base_url,
        "findings": dedupe_web_findings(findings)[:100],
        "raw": raw,
    }


def _build_research_query(discovered_targets: Dict[str, Dict[str, Any]], web_findings: List[Dict[str, Any]]) -> str:
    terms: List[str] = []

    for target_data in discovered_targets.values():
        services = target_data.get("services", {}) or {}
        for service in services.values():
            if not isinstance(service, dict):
                continue
            for field in ("service_name", "version", "banner"):
                value = str(service.get(field) or "").strip()
                if not value:
                    continue
                for token in value.replace("/", " ").split():
                    cleaned = token.strip(" ,:;()[]{}")
                    if len(cleaned) >= 3 and cleaned not in terms:
                        terms.append(cleaned)

    for finding in web_findings[:10]:
        path = str(finding.get("path") or "").strip()
        if path and path not in terms:
            terms.append(path)

    return " ".join(terms[:20]) or "automotive testbed striker live validation"


def _summarize_rag(results: Dict[str, Any]) -> Dict[str, str]:
    def _format(rows: List[Dict[str, Any]]) -> str:
        lines = []
        for row in rows[:5]:
            metadata = row.get("metadata") or {}
            doc_name = row.get("doc_name") or metadata.get("rel_path") or "unknown"
            score = row.get("score") or row.get("similarity") or 0
            snippet = str(row.get("chunk_text") or row.get("description") or "").replace("\n", " ").strip()
            lines.append(f"{doc_name} (score={score}): {snippet[:220]}")
        return "\n".join(lines) if lines else "none"

    return {
        "kb_top_hits": _format(results.get("kb_results", []) or []),
        "similar_findings": _format(results.get("findings_results", []) or []),
    }


async def _query_research(mission_id: str, target: str, query: str) -> Dict[str, Any]:
    _step(f"Running RAG lookup for query: {query[:120]}")
    from src.database.rag.rag_engine import RAGOrchestrator

    rag = RAGOrchestrator()
    return await rag.retrieve(
        query=query,
        source="both",
        top_k=LIVE_KB_TOP_K,
        filters={"mission_id": mission_id, "target_ip": target},
    )


def _attach_manual_intel(state: CyberState, target: str) -> None:
    services = state["discovered_targets"][target].get("services", {}) or {}
    for service in services.values():
        if not isinstance(service, dict):
            continue
        version = str(service.get("version", "") or "").lower()
        banner = str(service.get("banner", "") or "").lower()
        if "vsftpd 2.3.4" in version or "vsftpd 2.3.4" in banner:
            state["intelligence_findings"] = [
                {
                    "cve": "CVE-2011-2523",
                    "description": "Observed vsftpd 2.3.4 in live nmap output.",
                    "exploit_available": True,
                    "data": {"confidence": 0.95},
                }
            ]
            return


async def _execute_live_flow(
    mission_id: str,
) -> tuple[CyberState, str, Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    if not await _live_prereqs_ready():
        raise RuntimeError("Live attackbox MCP bridge or required tools are unavailable")

    bridge, original_get_tools = await _enable_tool_tracing()

    try:
        _step(f"Bootstrapping live striker mission: {mission_id}")
        state, raw_scan = await _scan_target_into_state(LIVE_TARGET, mission_id)
        print(f"[TRACE] NMAP_RAW:\n{raw_scan[:12000]}", flush=True)

        _step("Persisting discovered targets into the operational database")
        persist_state_update(
            state,
            {
                "mission_id": mission_id,
                "discovered_targets": state["discovered_targets"],
            },
        )

        web_result = await _collect_web_findings(state["discovered_targets"])
        state["web_findings"] = web_result["findings"]
        if web_result["raw"].get("web_content_enum"):
            print(f"[TRACE] WEB_CONTENT_ENUM_RAW:\n{web_result['raw']['web_content_enum'][:12000]}", flush=True)
        if web_result["raw"].get("web_nikto_scan"):
            print(f"[TRACE] WEB_NIKTO_RAW:\n{web_result['raw']['web_nikto_scan'][:12000]}", flush=True)
        if state["web_findings"]:
            _step(f"Persisting {len(state['web_findings'])} web findings into the operational database")
            persist_state_update(
                state,
                {
                    "mission_id": mission_id,
                    "web_findings": state["web_findings"],
                },
            )

        _step("Querying operational database for current target state")
        db_target_info = get_target_info(mission_id, LIVE_TARGET)
        _trace(
            "DB_TARGET_INFO",
            {
                "target_present": bool(db_target_info.get("target")),
                "services_count": len(db_target_info.get("services", []) or []),
                "findings_count": len(db_target_info.get("findings", []) or []),
                "sessions_count": len(db_target_info.get("sessions", []) or []),
            },
        )
        research_query = _build_research_query(state["discovered_targets"], state["web_findings"])
        rag_results = await _query_research(mission_id, LIVE_TARGET, research_query)
        _trace(
            "RAG_RESULT_COUNTS",
            {
                "kb_results": len(rag_results.get("kb_results", []) or []),
                "findings_results": len(rag_results.get("findings_results", []) or []),
            },
        )
        rag_summary = _summarize_rag(rag_results)

        _step("Attaching research and database summaries to research_cache")
        state["research_cache"] = {
            "query": research_query,
            "kb_top_hits": rag_summary["kb_top_hits"],
            "similar_findings": rag_summary["similar_findings"],
            "database_target_info": json.dumps(_safe_json(db_target_info), default=str)[:4000],
        }
        _attach_manual_intel(state, LIVE_TARGET)

        _step("Rendering striker context before invocation")
        print(f"[TRACE] STRIKER_CONTEXT:\n{striker_module._build_striker_context(state)[:20000]}", flush=True)

        _step("Invoking striker_node with assembled live evidence")
        result = await striker_module.striker_node(state)
        _step("Striker run completed; returning validation payload")
        return state, raw_scan, web_result, db_target_info, rag_results, result
    finally:
        bridge.get_tools_for_agent = original_get_tools


def _validate_live_result(
    state: CyberState,
    raw_scan: str,
    web_result: Dict[str, Any],
    db_target_info: Dict[str, Any],
    rag_results: Dict[str, Any],
    result: Dict[str, Any],
) -> Dict[str, Any]:
    _step("Validating live striker result")
    assert result["current_agent"] == "striker"
    assert result["iteration_count"] == 1
    assert not result.get("errors"), result.get("errors")
    assert state["discovered_targets"][LIVE_TARGET]["services"], (
        f"nmap results were not persisted into CyberState for {LIVE_TARGET}.\n{raw_scan}"
    )
    assert db_target_info["target"] is not None, "Target row should be queryable after persistence"
    assert db_target_info["services"], "Discovered services should be queryable from the database"
    assert "query" in state["research_cache"], "Research query should be stored in research_cache"
    assert "kb_top_hits" in state["research_cache"], "KB lookup summary should be attached"
    assert "database_target_info" in state["research_cache"], "DB lookup summary should be attached"

    assert "agent_log" in result and result["agent_log"], "agent_log should record the live attempt"
    log_entry = result["agent_log"][0]
    if hasattr(log_entry, "model_dump"):
        log_entry = log_entry.model_dump()

    findings = log_entry.get("findings") or {}
    assert findings or result.get("exploited_services"), "Live run should produce findings or an execution record"

    reasoning = str(log_entry.get("reasoning") or "")
    assert "TARGET INTELLIGENCE:" in reasoning
    assert "research_cache" not in reasoning.lower() or state["research_cache"]["query"] in str(state["research_cache"])

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
    reasoning_lower = reasoning.lower()
    assert (
        observed_services.intersection(search_terms)
        or observed_services.intersection(matched_terms)
        or observed_versions.intersection(search_terms)
        or any(service and service in reasoning_lower for service in observed_services)
        or any(version and version in reasoning_lower for version in observed_versions)
    ), "striker did not appear to consume the live nmap-derived evidence"

    summary = {
        "mission_id": state["mission_id"],
        "target": LIVE_TARGET,
        "execute_live": LIVE_STRIKER_EXECUTE,
        "open_ports": state["discovered_targets"][LIVE_TARGET]["ports"],
        "web_base_url": web_result["base_url"],
        "web_findings_count": len(state["web_findings"]),
        "db_services_count": len(db_target_info["services"]),
        "db_findings_count": len(db_target_info["findings"]),
        "rag_kb_hits": len(rag_results.get("kb_results", []) or []),
        "rag_finding_hits": len(rag_results.get("findings_results", []) or []),
        "exploited_services": _safe_json(result.get("exploited_services", [])),
        "agent_log": _safe_json(result.get("agent_log", [])),
    }
    _trace("STRIKER_RESULT", summary)

    if LIVE_STRIKER_EXECUTE and result.get("exploited_services"):
        attempt = result["exploited_services"][0]
        if hasattr(attempt, "model_dump"):
            attempt = attempt.model_dump()
        assert attempt.get("module"), "Live exploit attempt should record the chosen module"
    else:
        assert findings.get("status") in {"aborted", "no_candidate"}
        if findings.get("status") == "aborted":
            assert findings.get("module"), "Planning path should still select a module before approval gate"
            assert "Execution blocked pending manual approval." in reasoning
        else:
            assert "No acceptable Metasploit module matched" in reasoning

    return summary


def test_striker_automotive_live_scans_fuzzes_queries_db_then_runs_worker(monkeypatch):
    _step("Starting pytest live striker automotive test")
    mission_id = _mission_id()

    monkeypatch.setattr(
        striker_module,
        "require_manual_approval",
        lambda **kwargs: LIVE_STRIKER_EXECUTE,
    )

    try:
        state, raw_scan, web_result, db_target_info, rag_results, result = _run(_execute_live_flow(mission_id))
    except RuntimeError as exc:
        pytest.skip(str(exc))

    summary = _validate_live_result(
        state=state,
        raw_scan=raw_scan,
        web_result=web_result,
        db_target_info=db_target_info,
        rag_results=rag_results,
        result=result,
    )
    _step("Pytest validation complete")
    print(json.dumps(summary, indent=2, default=str))


def main() -> int:
    mission_id = _mission_id()
    _step(f"Starting direct live striker script run for mission {mission_id}")
    striker_module.require_manual_approval = lambda **kwargs: LIVE_STRIKER_EXECUTE

    try:
        state, raw_scan, web_result, db_target_info, rag_results, result = _run(_execute_live_flow(mission_id))
        summary = _validate_live_result(
            state=state,
            raw_scan=raw_scan,
            web_result=web_result,
            db_target_info=db_target_info,
            rag_results=rag_results,
            result=result,
        )
    except RuntimeError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except AssertionError as exc:
        print(f"[FAIL] {exc}")
        return 1

    _step("Direct script validation complete")
    print(json.dumps(summary, indent=2, default=str))
    print("[PASS] Striker automotive live test completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
