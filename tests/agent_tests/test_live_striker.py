"""
Live Striker planning integration test.

This is the canonical live Striker integration path for the current agent stack.
It gathers real recon evidence from the attackbox MCP bridge, enriches the mission
state with optional web-surface and research context, and then runs the real
OpenRouter-backed Striker worker.

The test intentionally forces manual approval to `False` so live execution stays
blocked. This validates current Striker planning, evidence consumption, and tool
selection without turning the test into an autonomous exploitation harness.

Run inside the agents container:
    docker exec vt-saiber-agents python3 -m pytest tests/agent_tests/test_live_striker.py -q -s
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytest.importorskip("psycopg2")
pytest.importorskip("pgvector")
pytest.importorskip("mcp")

import src.agents.striker as striker_module
from src.agents.fuzzer import FUZZER_ALLOWED_TOOLS, FuzzerAgent
from src.config import get_runtime_config
from src.database.librarian.cve_client import CVEClient
from src.database.librarian.models import ResearchEvidence
from src.database.librarian.osint_client import OSINTClient
from src.database.persistence import persist_state_update
from src.database.targets_repository import get_target_info
from src.main import build_initial_state
from src.mcp.mcp_tool_bridge import get_mcp_bridge, reset_mcp_bridge
from src.state.cyber_state import CyberState
from src.utils.agent_parsers import (
    dedupe_web_findings,
    extract_tool_output_text,
    parse_gobuster_output,
    parse_host_discovery_output,
    parse_nikto_output,
    parse_nmap_output,
    parse_service_records,
)
from src.utils.parsers import normalize_tool_result
from src.utils.tools import RuntimeTool


pytestmark = pytest.mark.live


LIVE_TARGET_HINT = (
    os.getenv("LIVE_STRIKER_TARGET")
    or os.getenv("LIVE_METASPLOIT_TARGET")
    or os.getenv("TARGET_HOST")
    or "automotive-testbed"
).strip() or "automotive-testbed"
LIVE_TARGET_SCOPE = (
    os.getenv("LIVE_STRIKER_SCOPE")
    or os.getenv("TARGET_SCOPE")
    or LIVE_TARGET_HINT
).strip() or LIVE_TARGET_HINT
LIVE_NMAP_PORTS = (
    os.getenv("LIVE_STRIKER_PORTS")
    or os.getenv("LIVE_METASPLOIT_PORTS")
    or "22,80,443,8000,8080,9555,9556"
).strip()
LIVE_NMAP_EXTRA_ARGS = (
    os.getenv("LIVE_STRIKER_EXTRA_ARGS")
    or os.getenv("LIVE_METASPLOIT_EXTRA_ARGS")
    or "-T4"
).strip()
LIVE_KB_TOP_K = int((os.getenv("LIVE_STRIKER_KB_TOP_K") or "5").strip() or "5")
LIVE_ENABLE_CVE = (os.getenv("LIVE_STRIKER_ENABLE_CVE") or "true").strip().lower() == "true"
LIVE_ENABLE_OSINT = (os.getenv("LIVE_STRIKER_ENABLE_OSINT") or "false").strip().lower() == "true"
LIVE_INCLUDE_VALIDATION_API = (os.getenv("LIVE_STRIKER_INCLUDE_VALIDATION_API") or "false").strip().lower() == "true"
TRACE_EVENTS: List[Dict[str, Any]] = []


def _step(message: str) -> None:
    print(f"[live-step] {message}", flush=True)


def _trace(label: str, payload: Dict[str, Any]) -> None:
    print(f"[live-trace] {label}: {json.dumps(_safe_json(payload), default=str)}", flush=True)


def _mission_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"live-striker-{stamp}"


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


def _result_preview(value: Any, max_chars: int = 4000) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(_safe_json(value), default=str, indent=2)
    return text[:max_chars] + ("...(truncated)" if len(text) > max_chars else "")


def _run(coro):
    async def _wrapped():
        try:
            return await coro
        finally:
            await reset_mcp_bridge()

    return asyncio.run(_wrapped())


def _base_state(target: str, mission_id: str) -> CyberState:
    state = build_initial_state(
        mission_goal=f"Plan an evidence-backed exploitation path for {target} from live recon without executing it",
        target_scope=[LIVE_TARGET_SCOPE],
        mission_id=mission_id,
    )
    state["current_agent"] = "striker"
    state["next_agent"] = None
    return state


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
                {"id": call_id, "tool": tool.name, "status": "ok", "elapsed_s": round(elapsed, 3)},
            )
            print(f"[live-trace] TOOL_RESULT[{call_id}]:\n{_result_preview(result)}", flush=True)
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


async def _enable_tool_tracing() -> tuple[Any, Any]:
    bridge = await get_mcp_bridge()
    original_get_tools = bridge.get_tools_for_agent

    def traced_get_tools(allowed_tools=None):
        tools = original_get_tools(allowed_tools)
        return [_wrap_tool_with_trace(tool) for tool in tools]

    bridge.get_tools_for_agent = traced_get_tools
    return bridge, original_get_tools


async def _bridge_tools_for_names(names: Iterable[str]) -> Dict[str, RuntimeTool]:
    bridge = await get_mcp_bridge()
    allowed = set(names)
    return {tool.name: tool for tool in bridge.get_tools_for_agent(allowed)}


async def _require_live_prereqs() -> None:
    cfg = get_runtime_config()
    if not cfg.openrouter_api_key or not cfg.openrouter_model:
        pytest.skip("Live Striker test requires OPENROUTER_API_KEY and OPENROUTER_MODEL.")

    try:
        bridge = await get_mcp_bridge()
        striker_tools = {tool.name for tool in bridge.get_tools_for_agent(striker_module.STRIKER_ALLOWED_TOOLS)}
        scout_tools = {tool.name for tool in bridge.get_tools_for_agent({"recon_host_discovery", "recon_service_probe"})}
    except Exception as exc:
        pytest.skip(f"Live attackbox MCP bridge is unavailable: {exc}")

    required_striker = {
        "msf_search_modules",
        "msf_get_module_options",
        "msf_run_exploit",
        "msf_run_auxiliary",
        "msf_list_sessions",
    }
    if not required_striker.issubset(striker_tools):
        missing = sorted(required_striker - striker_tools)
        pytest.skip(f"Striker live tools unavailable: missing {missing}")
    if "recon_service_probe" not in scout_tools:
        pytest.skip("Scout recon_service_probe tool is unavailable")


def _select_discovered_host(hosts: List[str], target_hint: str) -> str:
    hint = str(target_hint or "").strip().lower()
    for host in hosts:
        candidate = str(host).strip()
        if candidate.lower() == hint:
            return candidate
    for host in hosts:
        candidate = str(host).strip()
        if hint and hint in candidate.lower():
            return candidate
    return str(hosts[0]).strip()


async def _discover_target() -> tuple[str, str]:
    tools = await _bridge_tools_for_names({"recon_host_discovery", "recon_service_probe"})

    host_tool = tools.get("recon_host_discovery")
    if host_tool is not None:
        _step(f"Running host discovery for scope: {LIVE_TARGET_SCOPE}")
        raw_discovery = await host_tool.executor(targets=LIVE_TARGET_SCOPE, additional_args=LIVE_NMAP_EXTRA_ARGS)
        parsed = normalize_tool_result(raw_discovery)
        evidence_hosts = ((parsed.get("evidence") or {}).get("hosts") or []) if isinstance(parsed, dict) else []
        hosts = [str(host).strip() for host in evidence_hosts if str(host).strip()]
        hosts = hosts or parse_host_discovery_output(raw_discovery, max_hosts=8)
        if hosts:
            selected = _select_discovered_host(hosts, LIVE_TARGET_HINT)
            _step(f"Host discovery selected target: {selected}")
            return selected, extract_tool_output_text(raw_discovery) or str(raw_discovery)

    _step("Host discovery unavailable or empty; falling back to configured target hint")
    return LIVE_TARGET_HINT, ""


async def _scan_target_into_state(mission_id: str) -> tuple[CyberState, str, str]:
    target, discovery_raw = await _discover_target()
    tools = await _bridge_tools_for_names({"recon_service_probe"})
    nmap_tool = tools.get("recon_service_probe")
    if nmap_tool is None:
        raise RuntimeError("Live attackbox recon_service_probe tool is unavailable")

    _step(f"Running service probe against {target}")
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
    return state, discovery_raw, extract_tool_output_text(raw_scan) or str(raw_scan)


def _pick_web_base_url(discovered_targets: Dict[str, Dict[str, Any]]) -> Optional[str]:
    candidates: List[Dict[str, Any]] = []
    for ip, target_data in discovered_targets.items():
        if not isinstance(target_data, dict):
            continue
        services = target_data.get("services", {}) or {}
        for port in target_data.get("ports", []) or []:
            service = services.get(str(port)) or services.get(port)
            if not isinstance(service, dict):
                continue
            name = str(service.get("service_name", "") or "").lower()
            if name in {"http", "https", "http-proxy"}:
                candidates.append({"ip": ip, "port": int(port), "service_name": name})

    if not candidates:
        return None

    # Prefer the actual application surface over the testbed validation API on 9999.
    target = next((item for item in candidates if item["port"] != 9999), None)
    if target is None and not LIVE_INCLUDE_VALIDATION_API:
        return None
    if target is None:
        target = candidates[0]

    ip = target["ip"]
    port = int(target["port"])
    scheme = "https" if port == 443 else "http"
    if port in {80, 443}:
        return f"{scheme}://{ip}"
    return f"{scheme}://{ip}:{port}"


async def _collect_web_surface(discovered_targets: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    base_url = _pick_web_base_url(discovered_targets)
    if not base_url:
        _step("No HTTP target found; skipping web enumeration")
        return {"base_url": None, "findings": [], "fuzzing_runs": [], "raw": {}}

    _step(f"Collecting web surface findings from {base_url}")
    fuzzer = FuzzerAgent()
    tools = await _bridge_tools_for_names(FUZZER_ALLOWED_TOOLS)
    findings: List[Dict[str, Any]] = []
    fuzzing_runs: List[Dict[str, Any]] = []
    raw: Dict[str, str] = {}

    gobuster_tool = tools.get("web_content_enum")
    if gobuster_tool is not None:
        gobuster_raw = await gobuster_tool.executor(
            url=base_url,
            wordlist="/usr/share/wordlists/dirb/common.txt",
            additional_args="--delay 200ms",
        )
        raw["web_content_enum"] = extract_tool_output_text(gobuster_raw)
        parsed = parse_gobuster_output(
            gobuster_raw,
            base_url=base_url,
            max_depth=3,
            soft_404_statuses={404},
            scan_policy=fuzzer._scan_policy(),
        )
        findings.extend(parsed)
        fuzzing_runs.append(
            {
                "target": base_url,
                "tool": "web_content_enum",
                "status": "completed",
                "summary": f"Enumerated {len(parsed)} normalized directory findings",
            }
        )

    nikto_tool = tools.get("web_nikto_scan")
    if nikto_tool is not None:
        nikto_raw = await nikto_tool.executor(target=base_url, additional_args="")
        raw["web_nikto_scan"] = extract_tool_output_text(nikto_raw)
        parsed = parse_nikto_output(
            nikto_raw,
            base_url=base_url,
            max_depth=3,
            scan_policy=fuzzer._scan_policy(),
        )
        findings.extend(parsed)
        fuzzing_runs.append(
            {
                "target": base_url,
                "tool": "web_nikto_scan",
                "status": "completed",
                "summary": f"Captured {len(parsed)} normalized Nikto findings",
            }
        )

    return {
        "base_url": base_url,
        "findings": dedupe_web_findings(findings)[:100],
        "fuzzing_runs": fuzzing_runs,
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
        path = str(finding.get("path") or finding.get("url") or "").strip()
        if path and path not in terms:
            terms.append(path)
    return " ".join(terms[:20]) or f"{LIVE_TARGET_HINT} striker live planning"


def _build_service_clues(discovered_targets: Dict[str, Dict[str, Any]]) -> List[str]:
    clues: List[str] = []
    for target_data in discovered_targets.values():
        services = target_data.get("services", {}) or {}
        for service in services.values():
            if not isinstance(service, dict):
                continue
            clue = " ".join(
                str(service.get(key) or "").strip()
                for key in ("service_name", "version", "banner")
                if str(service.get(key) or "").strip()
            ).strip()
            if clue and clue not in clues:
                clues.append(clue)
    return clues[:10]


def _summarize_research_rows(rows: Iterable[Dict[str, Any]], *, limit: int = 5) -> str:
    lines: List[str] = []
    for row in list(rows)[:limit]:
        metadata = row.get("metadata") or {}
        doc_name = row.get("doc_name") or metadata.get("rel_path") or metadata.get("source_path") or "unknown"
        score = row.get("score") or row.get("similarity") or 0
        snippet = str(row.get("chunk_text") or row.get("description") or "").replace("\n", " ").strip()
        lines.append(f"{doc_name} (score={score}): {snippet[:220]}")
    return "\n".join(lines) if lines else "none"


def _format_evidence_rows(rows: Iterable[ResearchEvidence], *, limit: int = 5) -> str:
    lines: List[str] = []
    for evidence in list(rows)[:limit]:
        snippet = str(evidence.snippet or evidence.title).replace("\n", " ").strip()
        lines.append(f"{evidence.identifier} ({evidence.source_type}, score={evidence.score}): {snippet[:220]}")
    return "\n".join(lines) if lines else "none"


def _normalize_cve_findings(results: List[ResearchEvidence]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for evidence in results[:5]:
        references = list(evidence.metadata.get("references") or [])[:2]
        findings.append(
            {
                "source": "cve",
                "cve": str(evidence.metadata.get("cve") or evidence.identifier).strip().upper(),
                "description": str(evidence.snippet or evidence.title).strip(),
                "exploit_available": bool(evidence.metadata.get("known_exploited")),
                "confidence": float(evidence.score or 0.0),
                "citations": [evidence.reference, *references],
                "source_types": ["cve"],
                "source_status": {"cve": "ready"},
                "technical_params": {"cve": str(evidence.metadata.get("cve") or evidence.identifier).strip().upper()},
            }
        )
    return findings


def _normalize_osint_findings(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for row in results[:3]:
        title = str(row.get("title") or "").strip()
        snippet = str(row.get("snippet") or "").strip()
        findings.append(
            {
                "source": "osint",
                "description": f"{title}: {snippet}".strip(": "),
                "confidence": float(row.get("score") or 0.0),
                "citations": [str(row.get("url") or "").strip()],
                "is_osint_derived": True,
                "source_types": ["osint"],
                "source_status": {"osint": "ready"},
                "technical_params": {},
            }
        )
    return findings


def _attach_manual_fallback_intel(state: CyberState, target: str) -> None:
    services = state["discovered_targets"][target].get("services", {}) or {}
    for service in services.values():
        if not isinstance(service, dict):
            continue
        version = str(service.get("version", "") or "").lower()
        banner = str(service.get("banner", "") or "").lower()
        if "vsftpd 2.3.4" in version or "vsftpd 2.3.4" in banner:
            state["intelligence_findings"].append(
                {
                    "source": "fallback",
                    "cve": "CVE-2011-2523",
                    "description": "Observed vsftpd 2.3.4 in live service probe output.",
                    "exploit_available": True,
                    "confidence": 0.95,
                    "citations": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
                    "source_types": ["cve"],
                    "source_status": {"cve": "fallback"},
                    "technical_params": {"cve": "CVE-2011-2523"},
                }
            )
            return


def _dedupe_intelligence(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = (
            str(finding.get("source") or ""),
            str(finding.get("cve") or ""),
            str(finding.get("description") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


async def _query_rag(mission_id: str, target: str, query: str) -> Dict[str, Any]:
    from src.database.rag.rag_engine import RAGOrchestrator

    rag = RAGOrchestrator()
    return await rag.retrieve(
        query=query,
        source="both",
        top_k=LIVE_KB_TOP_K,
        filters={"mission_id": mission_id, "target_ip": target},
    )


async def _collect_research_enrichment(state: CyberState, mission_id: str, target: str) -> Dict[str, Any]:
    query = _build_research_query(state["discovered_targets"], state["web_findings"])
    service_clues = _build_service_clues(state["discovered_targets"])
    degraded_reasons: List[str] = []
    research_cache: Dict[str, Any] = {"query": query}
    intelligence_findings: List[Dict[str, Any]] = list(state.get("intelligence_findings", []) or [])
    db_target_info: Dict[str, Any] = {"target": None, "services": [], "findings": [], "sessions": []}
    rag_results: Dict[str, Any] = {"kb_results": [], "findings_results": []}
    cve_results: List[ResearchEvidence] = []
    osint_results: List[Dict[str, Any]] = []

    _step("Persisting current live evidence into the operational database")
    persist_state_update(
        state,
        {
            "mission_id": mission_id,
            "discovered_targets": state["discovered_targets"],
            "web_findings": state["web_findings"],
            "fuzzing_runs": state["fuzzing_runs"],
        },
    )

    try:
        db_target_info = get_target_info(mission_id, target)
        research_cache["database_target_info"] = json.dumps(_safe_json(db_target_info), default=str)[:4000]
    except Exception as exc:
        degraded_reasons.append(f"database query unavailable: {exc}")

    try:
        rag_results = await _query_rag(mission_id, target, query)
        research_cache["kb_top_hits"] = _summarize_research_rows(rag_results.get("kb_results", []) or [])
        research_cache["similar_findings"] = _summarize_research_rows(rag_results.get("findings_results", []) or [])
    except Exception as exc:
        degraded_reasons.append(f"rag retrieval unavailable: {exc}")

    if LIVE_ENABLE_CVE:
        try:
            cve_results = await CVEClient().search(query=query, service_clues=service_clues, max_results=5)
            if cve_results:
                intelligence_findings.extend(_normalize_cve_findings(cve_results))
                research_cache["cve_top_hits"] = _format_evidence_rows(cve_results)
        except Exception as exc:
            degraded_reasons.append(f"cve enrichment unavailable: {exc}")
    else:
        degraded_reasons.append("cve enrichment disabled")

    if LIVE_ENABLE_OSINT:
        try:
            osint_client = OSINTClient()
            if osint_client.is_configured():
                osint_results = await osint_client.search(query, max_results=3)
                if osint_results:
                    intelligence_findings.extend(_normalize_osint_findings(osint_results))
                    research_cache["osint_top_hits"] = json.dumps(_safe_json(osint_results[:3]), default=str)[:2000]
            else:
                degraded_reasons.append("osint enrichment not configured")
        except Exception as exc:
            degraded_reasons.append(f"osint enrichment unavailable: {exc}")
    else:
        degraded_reasons.append("osint enrichment disabled")

    if not intelligence_findings:
        _attach_manual_fallback_intel(state, target)
        intelligence_findings = list(state.get("intelligence_findings", []) or [])

    if degraded_reasons:
        research_cache["degraded_reasons"] = degraded_reasons

    return {
        "query": query,
        "db_target_info": db_target_info,
        "rag_results": rag_results,
        "cve_results": cve_results,
        "osint_results": osint_results,
        "research_cache": research_cache,
        "intelligence_findings": _dedupe_intelligence(intelligence_findings),
    }


async def _execute_live_flow(mission_id: str) -> Dict[str, Any]:
    await _require_live_prereqs()
    TRACE_EVENTS.clear()
    bridge, original_get_tools = await _enable_tool_tracing()

    try:
        state, discovery_raw, raw_scan = await _scan_target_into_state(mission_id)
        target = next(iter(state["discovered_targets"].keys()))
        print(f"[live-trace] HOST_DISCOVERY_RAW:\n{discovery_raw[:8000]}", flush=True)
        print(f"[live-trace] NMAP_RAW:\n{raw_scan[:12000]}", flush=True)

        web_result = await _collect_web_surface(state["discovered_targets"])
        state["web_findings"] = web_result["findings"]
        state["fuzzing_runs"] = web_result["fuzzing_runs"]
        if web_result["raw"].get("web_content_enum") and "Status:" in web_result["raw"]["web_content_enum"] and not state["web_findings"]:
            raise RuntimeError("Gobuster output contained findings but no normalized web_findings were produced.")
        if web_result["raw"].get("web_nikto_scan") and "+ [" in web_result["raw"]["web_nikto_scan"] and not state["web_findings"]:
            raise RuntimeError("Nikto output contained findings but no normalized web_findings were produced.")
        if web_result["raw"].get("web_content_enum"):
            print(f"[live-trace] WEB_CONTENT_ENUM_RAW:\n{web_result['raw']['web_content_enum'][:12000]}", flush=True)
        if web_result["raw"].get("web_nikto_scan"):
            print(f"[live-trace] WEB_NIKTO_RAW:\n{web_result['raw']['web_nikto_scan'][:12000]}", flush=True)

        enrichment = await _collect_research_enrichment(state, mission_id, target)
        state["research_cache"] = enrichment["research_cache"]
        state["intelligence_findings"] = enrichment["intelligence_findings"]

        persist_state_update(
            state,
            {
                "mission_id": mission_id,
                "research_cache": state["research_cache"],
                "intelligence_findings": state["intelligence_findings"],
            },
        )

        _step("Rendering Striker context")
        context_preview = striker_module._build_striker_context(state)
        print(f"[live-trace] STRIKER_CONTEXT:\n{context_preview[:20000]}", flush=True)

        _step("Running live Striker planning turn with approval forced off")
        striker_module.require_manual_approval = lambda **kwargs: False
        result = await striker_module.striker_node(state)

        return {
            "state": state,
            "target": target,
            "discovery_raw": discovery_raw,
            "raw_scan": raw_scan,
            "web_result": web_result,
            "db_target_info": enrichment["db_target_info"],
            "rag_results": enrichment["rag_results"],
            "cve_results": enrichment["cve_results"],
            "osint_results": enrichment["osint_results"],
            "result": result,
            "trace_events": list(TRACE_EVENTS),
        }
    finally:
        bridge.get_tools_for_agent = original_get_tools


def _extract_log_entry(result: Dict[str, Any]) -> Dict[str, Any]:
    logs = result.get("agent_log", []) or []
    if not logs:
        return {}
    entry = logs[0]
    return entry.model_dump() if hasattr(entry, "model_dump") else dict(entry)


def _validate_live_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    state = payload["state"]
    target = payload["target"]
    raw_scan = payload["raw_scan"]
    web_result = payload["web_result"]
    db_target_info = payload["db_target_info"]
    rag_results = payload["rag_results"]
    cve_results = payload["cve_results"]
    osint_results = payload["osint_results"]
    result = payload["result"]
    trace_events = payload["trace_events"]

    assert result["current_agent"] == "striker"
    assert result["iteration_count"] == 1
    assert not result.get("errors"), result.get("errors")
    assert state["discovered_targets"][target]["services"], (
        f"nmap results were not persisted into CyberState for {target}.\n{raw_scan}"
    )

    if web_result["base_url"]:
        assert state["fuzzing_runs"], "Web-target live runs should capture fuzzing/web-scan summaries"

    assert "query" in state["research_cache"], "Research query should be attached to research_cache"
    assert "agent_log" in result and result["agent_log"], "agent_log should capture the Striker live planning turn"
    assert trace_events, "Live test should record traceable MCP tool activity"

    trace_tool_names = {str(event.get("tool") or "") for event in trace_events}
    assert "recon_service_probe" in trace_tool_names
    assert trace_tool_names.intersection(striker_module.STRIKER_ALLOWED_TOOLS), (
        "Striker did not appear to invoke any allowed live tools during the planning turn"
    )

    log_entry = _extract_log_entry(result)
    findings = log_entry.get("findings") or {}
    reasoning = str(log_entry.get("reasoning") or "")
    reasoning_lower = reasoning.lower()

    assert "TARGET INTELLIGENCE:" in reasoning
    assert not result.get("active_sessions"), "Approval-forced planning runs must not open live sessions"

    observed_services = {
        str(service.get("service_name", "") or "").lower()
        for service in state["discovered_targets"][target]["services"].values()
        if isinstance(service, dict)
    }
    observed_versions = {
        str(service.get("version", "") or "").lower()
        for service in state["discovered_targets"][target]["services"].values()
        if isinstance(service, dict) and service.get("version")
    }
    search_terms = [str(term).lower() for term in findings.get("search_terms", [])]
    matched_terms = [str(term).lower() for term in findings.get("matched_terms", [])]
    assert (
        observed_services.intersection(search_terms)
        or observed_services.intersection(matched_terms)
        or observed_versions.intersection(search_terms)
        or any(service and service in reasoning_lower for service in observed_services)
        or any(version and version in reasoning_lower for version in observed_versions)
    ), "Striker did not appear to consume the live recon-derived evidence"

    assert findings, "Striker live planning run should record findings from the tool loop"
    assert findings.get("status") in {"approval_blocked", "no_candidate"} or findings.get("module") or findings.get("candidate_modules"), (
        "Planning run should either stop safely or record a module-selection path"
    )

    if findings.get("status") == "approval_blocked":
        assert "Execution blocked pending manual approval." in reasoning

    summary = {
        "mission_id": state["mission_id"],
        "target": target,
        "open_ports": state["discovered_targets"][target]["ports"],
        "web_base_url": web_result["base_url"],
        "web_findings_count": len(state["web_findings"]),
        "fuzzing_runs_count": len(state["fuzzing_runs"]),
        "intelligence_findings_count": len(state["intelligence_findings"]),
        "db_services_count": len(db_target_info.get("services", []) or []),
        "db_findings_count": len(db_target_info.get("findings", []) or []),
        "rag_kb_hits": len(rag_results.get("kb_results", []) or []),
        "rag_finding_hits": len(rag_results.get("findings_results", []) or []),
        "cve_hits": len(cve_results),
        "osint_hits": len(osint_results),
        "trace_tools": sorted(trace_tool_names),
        "selected_module": findings.get("selected_module") or findings.get("module"),
        "findings_status": findings.get("status"),
        "degraded_reasons": state["research_cache"].get("degraded_reasons", []),
    }
    _trace("LIVE_STRIKER_SUMMARY", summary)
    return summary


def test_live_striker_ingests_scan_fuzz_and_research_then_runs_planning_worker():
    mission_id = _mission_id()
    payload = _run(_execute_live_flow(mission_id))
    summary = _validate_live_payload(payload)
    print(json.dumps(summary, indent=2, default=str))


def main() -> int:
    mission_id = _mission_id()
    try:
        payload = _run(_execute_live_flow(mission_id))
        summary = _validate_live_payload(payload)
    except pytest.skip.Exception as exc:
        print(f"[live-skip] {exc}")
        return 0
    except RuntimeError as exc:
        print(f"[live-fail] {exc}")
        return 1
    except AssertionError as exc:
        print(f"[live-fail] {exc}")
        return 1

    print(json.dumps(summary, indent=2, default=str))
    print("[live-pass] Striker live planning test completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
