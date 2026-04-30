"""Shared helpers for opt-in v2 live tests."""

from __future__ import annotations

import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import pytest

from src.config import get_runtime_config
from src.main import build_initial_state
from src.state.cyber_state import CyberState
from src.utils.agent_parsers import dedupe_web_findings, parse_gobuster_output, parse_nikto_output
from src.v2.agents.scout.constants import ATTACKBOX_MCP_URL
from src.v2.execution.runner import _normalize_mcp_call_result


CAPTURED_TARGET = os.getenv("LIVE_STRIKER_TARGET") or os.getenv("TARGET_HOST") or "automotive-testbed"
CAPTURED_BASE_URL = os.getenv("LIVE_FUZZER_BASE_URL") or f"http://{CAPTURED_TARGET}:8000"
CAPTURED_SERVICES = [
    {"port": 22, "protocol": "tcp", "service_name": "ssh", "version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.14", "banner": None},
    {"port": 8000, "protocol": "tcp", "service_name": "http", "version": "Werkzeug httpd 3.1.8 (Python 3.10.12)", "banner": None},
    {"port": 8080, "protocol": "tcp", "service_name": "http", "version": "Werkzeug httpd 3.1.8 (Python 3.10.12)", "banner": None},
    {"port": 9555, "protocol": "tcp", "service_name": "trispen-sra?", "version": None, "banner": None},
    {"port": 9556, "protocol": "tcp", "service_name": "unknown", "version": None, "banner": None},
]
CAPTURED_SCAN_POLICY = {"methods": ["GET", "HEAD"], "max_depth": 3, "request_throttle_ms": 200, "soft_404_detection": True}
CAPTURED_GOBUSTER_RAW = {"result": {"status": "success", "raw": {"stdout": """
dashboard            (Status: 302) [Size: 199] [--> /login]
login                (Status: 200) [Size: 1206]
logout               (Status: 302) [Size: 199] [--> /login]
search               (Status: 405) [Size: 153]
settings             (Status: 302) [Size: 199] [--> /login]
upload               (Status: 405) [Size: 153]
"""}}}
CAPTURED_NIKTO_RAW = {"result": {"status": "success", "raw": {"stdout": """
+ Server: Werkzeug/3.1.8 Python/3.10.12
+ [013587] /: Suggested security header missing: referrer-policy.
+ [013587] /: Suggested security header missing: content-security-policy.
+ [600652] Python/3.10.12 appears to be outdated.
+ [999990] OPTIONS: Allowed HTTP Methods: GET, HEAD, OPTIONS .
"""}}}


def step(message: str) -> None:
    """Print a live-test progress line."""

    print(f"[v2-live] {message}", flush=True)


def require_live_openrouter() -> None:
    """Skip unless live OpenRouter-backed v2 tests are explicitly enabled."""

    if os.getenv("RUN_V2_LIVE_TESTS") != "1":
        pytest.skip("Set RUN_V2_LIVE_TESTS=1 to run live v2 tests")
    if not os.getenv("OPENROUTER_API_KEY"):
        pytest.skip("OPENROUTER_API_KEY is required for live v2 tests")
    if not os.getenv("OPENROUTER_MODEL"):
        pytest.skip("OPENROUTER_MODEL is required for live v2 tests")


def require_live_mcp() -> None:
    """Skip unless direct attackbox MCP live tests are explicitly enabled and reachable."""

    require_live_openrouter()
    pytest.importorskip("agents")
    if os.getenv("RUN_V2_LIVE_MCP_TESTS") != "1":
        pytest.skip("Set RUN_V2_LIVE_MCP_TESTS=1 to run MCP-backed v2 live tests")
    try:
        with urlopen(Request(ATTACKBOX_MCP_URL, method="GET"), timeout=3):
            return
    except HTTPError:
        return
    except (OSError, URLError) as exc:
        pytest.skip(f"Attackbox MCP server is not reachable at {ATTACKBOX_MCP_URL}: {exc}")


def base_state(
    *,
    mission_goal: str = "Run a bounded v2 live validation step",
    target_scope: list[str] | None = None,
    mission_id: str = "v2-live-test",
) -> CyberState:
    """Build a canonical live-test CyberState."""

    scope = target_scope or [live_target()]
    state = build_initial_state(mission_goal, scope, mission_id)
    state["next_agent"] = None
    return state


def live_target() -> str:
    """Return the configured live target host."""

    return (
        os.getenv("LIVE_SCOUT_TARGET")
        or os.getenv("LIVE_STRIKER_TARGET")
        or os.getenv("TARGET_HOST")
        or "automotive-testbed"
    ).strip()


def live_scope() -> str:
    """Return the configured live target scope."""

    return (os.getenv("TARGET_SCOPE") or os.getenv("LIVE_TARGET_SCOPE") or live_target()).strip()


def fuzzer_base_url() -> str:
    """Return the configured web base URL for fuzzer live tests."""

    configured = (os.getenv("LIVE_FUZZER_BASE_URL") or "").strip()
    if configured:
        return configured
    return CAPTURED_BASE_URL


def discovered_http_state(base_url: str | None = None) -> CyberState:
    """Build a state with one known HTTP service for fuzzer/striker tests."""

    url = urlparse(base_url or fuzzer_base_url())
    host = url.hostname or live_target()
    port = url.port or (443 if url.scheme == "https" else 80)
    service_name = "https" if url.scheme == "https" else "http"
    state = base_state(
        mission_goal=f"Validate v2 web tooling against {host}",
        target_scope=[live_scope()],
        mission_id="v2-live-web",
    )
    state["discovered_targets"] = {
        host: {
            "ip_address": host,
            "ports": [port],
            "services": {
                str(port): {
                    "port": port,
                    "protocol": "tcp",
                    "service_name": service_name,
                    "version": os.getenv("LIVE_FUZZER_SERVICE_VERSION", ""),
                    "banner": "",
                }
            },
        }
    }
    return state


def captured_web_findings(base_url: str | None = None) -> list[dict[str, Any]]:
    """Return normalized captured web findings from the legacy automotive test."""

    target_url = base_url or CAPTURED_BASE_URL
    findings = parse_gobuster_output(
        CAPTURED_GOBUSTER_RAW,
        base_url=target_url,
        max_depth=3,
        soft_404_statuses={404},
        scan_policy=CAPTURED_SCAN_POLICY,
    )
    findings.extend(
        parse_nikto_output(
            CAPTURED_NIKTO_RAW,
            base_url=target_url,
            max_depth=3,
            scan_policy=CAPTURED_SCAN_POLICY,
        )
    )
    return dedupe_web_findings(findings)[:100]


def captured_automotive_state(*, mission_id: str = "v2-live-captured") -> CyberState:
    """Build a live-test state seeded with the precomputed automotive evidence."""

    state = base_state(
        mission_goal=f"Use the precomputed automotive evidence for a bounded v2 live validation on {CAPTURED_TARGET}",
        target_scope=[live_scope()],
        mission_id=mission_id,
    )
    state["discovered_targets"] = {
        CAPTURED_TARGET: {
            "ip_address": CAPTURED_TARGET,
            "ports": [service["port"] for service in CAPTURED_SERVICES],
            "services": {str(service["port"]): dict(service) for service in CAPTURED_SERVICES},
        }
    }
    state["web_findings"] = captured_web_findings(CAPTURED_BASE_URL)
    state["fuzzing_runs"] = [
        {"target": CAPTURED_BASE_URL, "tool": "web_content_enum", "status": "captured"},
        {"target": CAPTURED_BASE_URL, "tool": "web_nikto_scan", "status": "captured"},
    ]
    state["research_cache"] = {"v2_live_captured": research_seed()}
    state["intelligence_findings"] = [
        {
            "source": "captured_cve_seed",
            "description": "Captured automotive context indicates HTTP Werkzeug services and SSH exposure.",
            "confidence": 0.75,
            "citations": ["legacy-captured-striker-test"],
            "source_types": ["captured"],
            "service_name": "http",
            "service_version": "Werkzeug httpd 3.1.8 (Python 3.10.12)",
        }
    ]
    return state


async def auto_detect_live_session() -> tuple[str, str] | None:
    """Pick the first live Metasploit session from the attackbox MCP server."""

    try:
        from agents.mcp import MCPServerStreamableHttp
    except Exception:
        return None

    url = os.getenv("MCP_ATTACKBOX_URL") or os.getenv("ATTACKBOX_MCP_URL") or ATTACKBOX_MCP_URL
    server = MCPServerStreamableHttp(name="attackbox", params={"url": url}, cache_tools_list=False)
    try:
        if hasattr(server, "__aenter__"):
            async with server:
                raw = await server.call_tool("msf_list_sessions", {})
        else:
            await server.connect()
            raw = await server.call_tool("msf_list_sessions", {})
            await server.close()
    except Exception as exc:
        step(f"Could not auto-detect resident session from {url}: {exc}")
        return None

    payload = _normalize_mcp_call_result(raw)
    if not isinstance(payload, dict):
        return None
    sessions = payload.get("sessions") or (payload.get("evidence") or {}).get("sessions")
    if not isinstance(sessions, dict) or not sessions:
        return None
    session_id, info = next(iter(sessions.items()))
    target = ""
    if isinstance(info, dict):
        target = str(info.get("target_host") or info.get("session_host") or info.get("tunnel_peer") or "").strip()
    return str(session_id), target or live_target()


def research_seed() -> dict[str, Any]:
    """Return a compact research-cache entry for striker live planning."""

    return {
        "summary": "Live v2 test seed: use only bounded, approval-gated validation paths.",
        "technical_params": {},
        "is_osint_derived": False,
        "confidence": 0.65,
        "citations": ["live-test:seed"],
        "conflicting_sources": None,
        "source_types": ["test_seed"],
        "source_status": {"kb": "skipped", "findings": "skipped", "cve": "skipped", "osint": "skipped", "llm": "skipped"},
        "degraded_reasons": [],
    }


class FakeRag:
    """Tiny retrieval double used by live librarian synthesis tests."""

    async def retrieve(self, query: str, source: str = "both", top_k: int = 5, filters=None):
        kb_item = {
            "doc_name": "v2-live-fixture.md",
            "score": 0.92,
            "chunk_text": "Use careful reconnaissance, cite evidence, and avoid autonomous exploitation.",
        }
        if source == "kb":
            return {"kb_results": [kb_item]}
        if source == "findings":
            return {"findings_results": []}
        return {"kb_results": [kb_item], "findings_results": []}


def runtime_summary() -> dict[str, Any]:
    """Return non-secret runtime details for live-test traces."""

    cfg = get_runtime_config()
    return {
        "model": cfg.openrouter_model,
        "base_url": cfg.openrouter_base_url,
        "attackbox_mcp_url": ATTACKBOX_MCP_URL,
    }
