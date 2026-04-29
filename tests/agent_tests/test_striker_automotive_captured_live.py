"""
Live Striker planning test seeded from captured automotive evidence.

This test avoids live recon, gobuster, Nikto, CVE lookup, and OSINT lookup.
Instead, it loads pre-given automotive target evidence captured from a prior
run and then executes only the live Striker planning/tool loop.

Run inside the agents container:
    docker exec vt-saiber-agents python3 -m pytest tests/agent_tests/test_striker_automotive_captured_live.py -q -s
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytest.importorskip("mcp")

import src.agents.striker as striker_module
from src.config import get_runtime_config
from src.main import build_initial_state
from src.mcp.mcp_tool_bridge import get_mcp_bridge, reset_mcp_bridge
from src.state.cyber_state import CyberState
from src.utils.agent_parsers import dedupe_web_findings, parse_gobuster_output, parse_nikto_output
from src.utils.tools import RuntimeTool


pytestmark = pytest.mark.live


CAPTURED_TARGET = "172.20.0.5"
CAPTURED_BASE_URL = "http://172.20.0.5:8000"
TRACE_EVENTS: List[Dict[str, Any]] = []
CAPTURED_SCAN_POLICY = {
    "methods": ["GET", "HEAD"],
    "max_depth": 3,
    "request_throttle_ms": 200,
    "soft_404_detection": True,
}
CAPTURED_STRIKER_TIMEOUT_SECONDS = int((os.getenv("LIVE_STRIKER_TIMEOUT_SECONDS") or "180").strip() or "180")

CAPTURED_SERVICES = [
    {
        "port": 22,
        "protocol": "tcp",
        "service_name": "ssh",
        "version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 (Ubuntu Linux; protocol 2.0)",
        "banner": None,
    },
    {
        "port": 8000,
        "protocol": "tcp",
        "service_name": "http",
        "version": "Werkzeug httpd 3.1.8 (Python 3.10.12)",
        "banner": None,
    },
    {
        "port": 8080,
        "protocol": "tcp",
        "service_name": "http",
        "version": "Werkzeug httpd 3.1.8 (Python 3.10.12)",
        "banner": None,
    },
    {
        "port": 9555,
        "protocol": "tcp",
        "service_name": "trispen-sra?",
        "version": None,
        "banner": None,
    },
    {
        "port": 9556,
        "protocol": "tcp",
        "service_name": "unknown",
        "version": None,
        "banner": None,
    },
]

CAPTURED_GOBUSTER_RAW = {
    "result": {
        "status": "success",
        "summary": f"Enumerated web content for {CAPTURED_BASE_URL}",
        "evidence": {"paths": []},
        "raw": {
            "command": f"/usr/bin/gobuster dir -u {CAPTURED_BASE_URL} -w /usr/share/wordlists/dirb/common.txt --no-error --delay 200ms",
            "stdout": """===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.0.5:8000
[+] Method:                  GET
[+] Threads:                 10
[+] Delay:                   200ms
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
dashboard            (Status: 302) [Size: 199] [--> /login]
login                (Status: 200) [Size: 1206]
logout               (Status: 302) [Size: 199] [--> /login]
search               (Status: 405) [Size: 153]
settings             (Status: 302) [Size: 199] [--> /login]
upload               (Status: 405) [Size: 153]
===============================================================
Finished
===============================================================
""",
        },
    }
}

CAPTURED_NIKTO_RAW = {
    "result": {
        "status": "success",
        "summary": "web_nikto_scan completed with exit code 0",
        "evidence": {},
        "raw": {
            "command": f"nikto -h {CAPTURED_BASE_URL}",
            "stdout": """- Nikto v2.6.0
---------------------------------------------------------------------------
+ Your Nikto installation is out of date.
+ Target IP:          172.20.0.5
+ Target Hostname:    172.20.0.5
+ Target Port:        8000
+ Platform:           Unknown
+ Start Time:         2026-04-29 15:26:14 (GMT0)
---------------------------------------------------------------------------
+ Server: Werkzeug/3.1.8 Python/3.10.12
+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.
+ [013587] /: Suggested security header missing: referrer-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
+ [013587] /: Suggested security header missing: x-content-type-options. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
+ [013587] /: Suggested security header missing: permissions-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
+ [013587] /: Suggested security header missing: content-security-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
+ [013587] /: Suggested security header missing: strict-transport-security. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
+ [600652] Python/3.10.12 appears to be outdated (current is at least 3.13.1).
+ [999990] OPTIONS: Allowed HTTP Methods: GET, HEAD, OPTIONS .
+ [007342] /: X-Frame-Options header is deprecated and was replaced with the Content-Security-Policy HTTP header with the frame-ancestors directive. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
+ [007352] /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ 8268 requests: 0 errors and 9 items reported on the remote host
+ End Time:           2026-04-29 15:26:56 (GMT0) (42 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
""",
        },
    }
}

CAPTURED_RESEARCH_CACHE = {
    "query": "ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 Linux protocol 2.0 http Werkzeug httpd 3.1.8 Python 3.10.12 trispen-sra? unknown",
    "database_target_info": json.dumps(
        {
            "target": {
                "ip_address": CAPTURED_TARGET,
                "os_guess": None,
                "hostname": None,
            },
            "services": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service_name": "ssh",
                    "service_version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 (Ubuntu Linux; protocol 2.0)",
                },
                {
                    "port": 8000,
                    "protocol": "tcp",
                    "service_name": "http",
                    "service_version": "Werkzeug httpd 3.1.8 (Python 3.10.12)",
                },
                {
                    "port": 8080,
                    "protocol": "tcp",
                    "service_name": "http",
                    "service_version": "Werkzeug httpd 3.1.8 (Python 3.10.12)",
                },
                {
                    "port": 9555,
                    "protocol": "tcp",
                    "service_name": "trispen-sra?",
                    "service_version": None,
                },
                {
                    "port": 9556,
                    "protocol": "tcp",
                    "service_name": "unknown",
                    "service_version": None,
                },
            ],
            "findings": [],
            "sessions": [],
        }
    ),
    "kb_top_hits": "none",
    "similar_findings": "none",
    "cve_top_hits": (
        "CVE-2025-54424 (cve, score=0.81): 1Panel is a web interface and MCP Server that manages websites, files, "
        "containers, databases, and LLMs on a Linux server.\n"
        "CVE-2003-1110 (cve, score=0.75): The Session Initiation Protocol (SIP) implementation in Columbia SIP User Agent.\n"
        "CVE-2000-0142 (cve, score=0.5): Timbuktu Pro denial of service.\n"
        "CVE-2002-1935 (cve, score=0.5): Pingtel Xpressa predictable SIP values.\n"
        "CVE-2004-2475 (cve, score=0.43): Google Toolbar about.html XSS."
    ),
    "degraded_reasons": ["osint enrichment disabled"],
}

CAPTURED_INTELLIGENCE_FINDINGS = [
    {
        "source": "cve",
        "cve": "CVE-2025-54424",
        "description": (
            "1Panel is a web interface and MCP Server that manages websites, files, containers, databases, and LLMs "
            "on a Linux server. In versions 2.0.5 and below, incomplete certificate verification can lead to "
            "unauthorized access and remote code execution."
        ),
        "confidence": 0.81,
        "citations": ["captured-output2"],
        "source_types": ["cve"],
        "source_status": {"cve": "captured"},
        "service_name": "http",
        "service_version": "Werkzeug httpd 3.1.8 (Python 3.10.12)",
    },
    {
        "source": "cve",
        "cve": "CVE-2003-1110",
        "description": "SIP implementation flaw allowing denial of service or code execution via crafted INVITE messages.",
        "confidence": 0.75,
        "citations": ["captured-output2"],
        "source_types": ["cve"],
        "source_status": {"cve": "captured"},
        "service_name": "http",
    },
]


def _step(message: str) -> None:
    print(f"[captured-step] {message}", flush=True)


def _trace(label: str, payload: Dict[str, Any]) -> None:
    print(f"[captured-trace] {label}: {json.dumps(_safe_json(payload), default=str)}", flush=True)


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


def _mission_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"captured-striker-{stamp}"


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
            print(f"[captured-trace] TOOL_RESULT[{call_id}]:\n{_result_preview(result)}", flush=True)
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


async def _require_live_prereqs() -> None:
    cfg = get_runtime_config()
    if not cfg.openrouter_api_key or not cfg.openrouter_model:
        pytest.skip("Captured Striker live test requires OPENROUTER_API_KEY and OPENROUTER_MODEL.")

    try:
        bridge = await get_mcp_bridge()
        striker_tools = {tool.name for tool in bridge.get_tools_for_agent(striker_module.STRIKER_ALLOWED_TOOLS)}
    except Exception as exc:
        pytest.skip(f"Live attackbox MCP bridge is unavailable: {exc}")

    required = {
        "msf_search_modules",
        "msf_get_module_options",
        "msf_run_exploit",
        "msf_run_auxiliary",
        "msf_list_sessions",
    }
    if not required.issubset(striker_tools):
        missing = sorted(required - striker_tools)
        pytest.skip(f"Striker live tools unavailable: missing {missing}")


def _captured_web_findings() -> List[Dict[str, Any]]:
    findings = parse_gobuster_output(
        CAPTURED_GOBUSTER_RAW,
        base_url=CAPTURED_BASE_URL,
        max_depth=3,
        soft_404_statuses={404},
        scan_policy=CAPTURED_SCAN_POLICY,
    )
    findings.extend(
        parse_nikto_output(
            CAPTURED_NIKTO_RAW,
            base_url=CAPTURED_BASE_URL,
            max_depth=3,
            scan_policy=CAPTURED_SCAN_POLICY,
        )
    )
    return dedupe_web_findings(findings)[:100]


def _captured_state(mission_id: str) -> CyberState:
    state = build_initial_state(
        mission_goal=f"Plan an evidence-backed exploitation path for {CAPTURED_TARGET} from captured recon without executing it",
        target_scope=[CAPTURED_TARGET],
        mission_id=mission_id,
    )
    state["current_agent"] = "striker"
    state["next_agent"] = None
    state["discovered_targets"] = {
        CAPTURED_TARGET: {
            "ip_address": CAPTURED_TARGET,
            "ports": [service["port"] for service in CAPTURED_SERVICES],
            "services": {str(service["port"]): dict(service) for service in CAPTURED_SERVICES},
        }
    }
    state["web_findings"] = _captured_web_findings()
    state["fuzzing_runs"] = [
        {
            "target": CAPTURED_BASE_URL,
            "tool": "web_content_enum",
            "status": "captured",
            "summary": "Loaded normalized gobuster findings from captured output2.txt evidence",
        },
        {
            "target": CAPTURED_BASE_URL,
            "tool": "web_nikto_scan",
            "status": "captured",
            "summary": "Loaded normalized Nikto findings from captured output2.txt evidence",
        },
    ]
    state["research_cache"] = dict(CAPTURED_RESEARCH_CACHE)
    state["intelligence_findings"] = [dict(item) for item in CAPTURED_INTELLIGENCE_FINDINGS]
    return state


async def _execute_captured_live_flow(mission_id: str) -> Dict[str, Any]:
    await _require_live_prereqs()
    TRACE_EVENTS.clear()
    bridge, original_get_tools = await _enable_tool_tracing()

    try:
        _step("Loading captured automotive evidence into Striker state")
        state = _captured_state(mission_id)
        context_preview = striker_module._build_striker_context(state)
        preloaded_web_findings = list(state.get("web_findings", []) or [])
        preloaded_web_findings_count = len(preloaded_web_findings)
        preloaded_web_findings_preview = [
            {
                "path": finding.get("path"),
                "status_code": finding.get("status_code"),
                "is_interesting": finding.get("is_interesting"),
            }
            for finding in preloaded_web_findings[:5]
            if isinstance(finding, dict)
        ]

        _trace(
            "CAPTURED_EVIDENCE_SUMMARY",
            {
                "target": CAPTURED_TARGET,
                "ports": state["discovered_targets"][CAPTURED_TARGET]["ports"],
                "web_findings_count": preloaded_web_findings_count,
                "web_findings_preview": preloaded_web_findings_preview,
                "research_keys": sorted((state.get("research_cache") or {}).keys()),
                "intelligence_count": len(state["intelligence_findings"]),
            },
        )
        print(f"[captured-trace] STRIKER_CONTEXT:\n{context_preview[:20000]}", flush=True)

        _step("Running live Striker planning turn with approval forced off")
        _trace(
            "STRIKER_CALL_START",
            {
                "timeout_seconds": CAPTURED_STRIKER_TIMEOUT_SECONDS,
                "preloaded_web_findings": preloaded_web_findings_count,
                "preloaded_intelligence_findings": len(state.get("intelligence_findings", []) or []),
            },
        )
        striker_module.require_manual_approval = lambda **kwargs: False
        try:
            result = await asyncio.wait_for(
                striker_module.striker_node(state),
                timeout=CAPTURED_STRIKER_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise RuntimeError(
                "Captured-state Striker planning turn timed out before returning or producing tool trace output. "
                f"Increase LIVE_STRIKER_TIMEOUT_SECONDS if the model is just slow. Current timeout={CAPTURED_STRIKER_TIMEOUT_SECONDS}s."
            ) from exc
        _trace(
            "STRIKER_CALL_END",
            {
                "agent_log_entries": len(result.get("agent_log", []) or []),
                "error_count": len(result.get("errors", []) or []),
                "active_sessions": len(result.get("active_sessions", {}) or {}),
            },
        )

        return {
            "state": state,
            "context_preview": context_preview,
            "preloaded_web_findings_count": preloaded_web_findings_count,
            "preloaded_web_findings_preview": preloaded_web_findings_preview,
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


def _validate_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    context_preview = payload["context_preview"]
    preloaded_web_findings_count = int(payload.get("preloaded_web_findings_count") or 0)
    preloaded_web_findings_preview = payload.get("preloaded_web_findings_preview") or []
    result = payload["result"]
    trace_events = payload["trace_events"]

    assert result["current_agent"] == "striker"
    assert result["iteration_count"] == 1
    assert not result.get("errors"), result.get("errors")
    assert preloaded_web_findings_count > 0, (
        "Captured-state test should preload normalized web findings. "
        f"Preview seen by test: {preloaded_web_findings_preview}"
    )
    assert "/dashboard" in context_preview
    assert "/login" in context_preview
    assert "RELEVANT WEB FINDINGS:" in context_preview
    assert "CANDIDATE PATHS:" in context_preview
    assert "http/8000" in context_preview
    assert "http/8080" in context_preview
    assert "degraded_reasons" in context_preview

    trace_tool_names = {str(event.get("tool") or "") for event in trace_events}
    assert trace_events, "Captured-state live test should still record live Striker tool activity"
    assert trace_tool_names.intersection(striker_module.STRIKER_ALLOWED_TOOLS), (
        "Striker did not invoke any allowed live tools during the captured-state planning turn"
    )
    assert trace_tool_names.isdisjoint({"recon_host_discovery", "recon_service_probe", "web_content_enum", "web_nikto_scan"}), (
        "Captured-state test should not run live recon or web scans"
    )

    log_entry = _extract_log_entry(result)
    findings = log_entry.get("findings") or {}
    reasoning = str(log_entry.get("reasoning") or "")
    reasoning_lower = reasoning.lower()
    state = payload["state"]
    observed_services = {
        str(service.get("service_name", "") or "").lower()
        for service in state["discovered_targets"][CAPTURED_TARGET]["services"].values()
        if isinstance(service, dict)
    }
    observed_versions = {
        str(service.get("version", "") or "").lower()
        for service in state["discovered_targets"][CAPTURED_TARGET]["services"].values()
        if isinstance(service, dict) and service.get("version")
    }
    search_terms = [str(term).lower() for term in findings.get("search_terms", [])]
    matched_terms = [str(term).lower() for term in findings.get("matched_terms", [])]

    assert "TARGET INTELLIGENCE:" in reasoning
    assert not result.get("active_sessions"), "Approval-forced planning runs must not open live sessions"
    assert findings, "Striker captured-state run should record findings from the tool loop"
    assert findings.get("status") in {"aborted", "no_candidate"} or findings.get("module") or findings.get("candidate_modules"), (
        "Planning run should either stop safely or record a module-selection path"
    )
    assert (
        observed_services.intersection(search_terms)
        or observed_services.intersection(matched_terms)
        or observed_versions.intersection(search_terms)
        or any(service and service in reasoning_lower for service in observed_services)
        or any(version and version in reasoning_lower for version in observed_versions)
    ), (
        "Striker reasoning did not appear to consume the captured evidence"
    )

    if findings.get("status") == "aborted":
        assert "Execution blocked pending manual approval." in reasoning

    summary = {
        "mission_id": state["mission_id"],
        "target": CAPTURED_TARGET,
        "open_ports": state["discovered_targets"][CAPTURED_TARGET]["ports"],
        "web_findings_count": len(state["web_findings"]),
        "trace_tools": sorted(trace_tool_names),
        "selected_module": findings.get("module") or findings.get("selected_module"),
        "findings_status": findings.get("status") or findings.get("stop_reason"),
    }
    _trace("CAPTURED_STRIKER_SUMMARY", summary)
    return summary


def test_striker_live_from_captured_automotive_evidence():
    mission_id = _mission_id()
    payload = _run(_execute_captured_live_flow(mission_id))
    summary = _validate_payload(payload)
    print(json.dumps(summary, indent=2, default=str))


def main() -> int:
    mission_id = _mission_id()
    try:
        payload = _run(_execute_captured_live_flow(mission_id))
        summary = _validate_payload(payload)
    except pytest.skip.Exception as exc:
        print(f"[captured-skip] {exc}")
        return 0
    except RuntimeError as exc:
        print(f"[captured-fail] {exc}")
        return 1
    except AssertionError as exc:
        print(f"[captured-fail] {exc}")
        return 1

    print(json.dumps(summary, indent=2, default=str))
    print("[captured-pass] Striker captured-state live test completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
