"""Shared helpers for directly runnable live tests."""

from __future__ import annotations

import os
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import pytest

from src.config import get_runtime_config
from src.main import build_initial_state
from src.state.cyber_state import CyberState
from src.core.agent_parsers import dedupe_web_findings, parse_gobuster_output, parse_nikto_output
from src.agents.scout.constants import ATTACKBOX_MCP_URL
from src.runtime.execution import _normalize_mcp_call_result


CAPTURED_TARGET = "automotive-testbed"
CAPTURED_TARGET_IP = "172.20.0.5"
CAPTURED_BASE_URL = f"http://{CAPTURED_TARGET}:8000"
CAPTURED_SERVICES = [
    {"port": 22, "protocol": "tcp", "service_name": "ssh", "version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.14", "banner": None},
    {"port": 8000, "protocol": "tcp", "service_name": "http", "version": "Werkzeug httpd 3.1.8 (Python 3.10.12)", "banner": None},
    {"port": 8080, "protocol": "tcp", "service_name": "http", "version": "Werkzeug httpd 3.1.8 (Python 3.10.12)", "banner": None},
    {"port": 9555, "protocol": "tcp", "service_name": "trispen-sra?", "version": None, "banner": None},
    {"port": 9556, "protocol": "tcp", "service_name": "unknown", "version": None, "banner": None},
]
CAPTURED_SCAN_POLICY = {"methods": ["GET", "HEAD"], "max_depth": 3, "request_throttle_ms": 200, "soft_404_detection": True}
CAPTURED_NMAP_RAW = """
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for automotive-testbed (172.20.0.5)
Host is up (0.000041s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http        Werkzeug httpd 3.1.8 (Python 3.10.12)
8080/tcp open  http        Werkzeug httpd 3.1.8 (Python 3.10.12)
9555/tcp open  trispen-sra?
9556/tcp open  unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned.
"""
CAPTURED_GOBUSTER_RAW = {"result": {"status": "success", "raw": {"stdout": """
===============================================================
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
"""}}}
CAPTURED_NIKTO_RAW = {"result": {"status": "success", "raw": {"stdout": """
+ Nikto.6.0
+ Target IP:          172.20.0.5
+ Target Hostname:    172.20.0.5
+ Target Port:        8000
+ Server: Werkzeug/3.1.8 Python/3.10.12
+ [013587] /: Suggested security header missing: referrer-policy.
+ [013587] /: Suggested security header missing: x-content-type-options.
+ [013587] /: Suggested security header missing: permissions-policy.
+ [013587] /: Suggested security header missing: content-security-policy.
+ [013587] /: Suggested security header missing: strict-transport-security.
+ [600652] Python/3.10.12 appears to be outdated.
+ [999990] OPTIONS: Allowed HTTP Methods: GET, HEAD, OPTIONS .
+ [007342] /: X-Frame-Options header is deprecated and was replaced by CSP frame-ancestors.
+ [007352] /: The X-Content-Type-Options header is not set.
+ 8268 requests: 0 errors and 9 items reported on the remote host
"""}}}
CAPTURED_RESEARCH_CACHE = {
    "query": "ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 Linux protocol 2.0 http Werkzeug httpd 3.1.8 Python 3.10.12 trispen-sra? unknown",
    "database_target_info": json.dumps(
        {
            "target": {"ip_address": CAPTURED_TARGET_IP, "os_guess": None, "hostname": None},
            "services": [
                {"port": 22, "protocol": "tcp", "service_name": "ssh", "service_version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 (Ubuntu Linux; protocol 2.0)"},
                {"port": 8000, "protocol": "tcp", "service_name": "http", "service_version": "Werkzeug httpd 3.1.8 (Python 3.10.12)"},
                {"port": 8080, "protocol": "tcp", "service_name": "http", "service_version": "Werkzeug httpd 3.1.8 (Python 3.10.12)"},
                {"port": 9555, "protocol": "tcp", "service_name": "trispen-sra?", "service_version": None},
                {"port": 9556, "protocol": "tcp", "service_name": "unknown", "service_version": None},
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
        "CVE-2003-1110 (cve, score=0.75): The Session Initiation Protocol implementation in Columbia SIP User Agent.\n"
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
        "citations": ["captured-evidence"],
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
        "citations": ["captured-evidence"],
        "source_types": ["cve"],
        "source_status": {"cve": "captured"},
        "service_name": "http",
    },
]


def step(message: str) -> None:
    """Print a live-test progress line."""

    print(f"[live] {message}", flush=True)


def require_live_openrouter() -> None:
    """Skip unless the production OpenRouter config is available."""

    if not os.getenv("OPENROUTER_API_KEY"):
        pytest.skip("OPENROUTER_API_KEY is required for live tests")
    if not os.getenv("OPENROUTER_MODEL"):
        pytest.skip("OPENROUTER_MODEL is required for live tests")


def require_live_mcp() -> None:
    """Skip unless direct attackbox MCP is reachable."""

    require_live_openrouter()
    pytest.importorskip("agents")
    try:
        with urlopen(Request(ATTACKBOX_MCP_URL, method="GET"), timeout=3):
            return
    except HTTPError:
        return
    except (OSError, URLError) as exc:
        pytest.skip(f"Attackbox MCP server is not reachable at {ATTACKBOX_MCP_URL}: {exc}")


def base_state(
    *,
    mission_goal: str = "Run a bounded live validation step",
    target_scope: list[str] | None = None,
    mission_id: str = "live-test",
) -> CyberState:
    """Build a canonical live-test CyberState."""

    scope = target_scope or [live_target()]
    state = build_initial_state(mission_goal, scope, mission_id)
    state["next_agent"] = None
    return state


def live_target() -> str:
    """Return the fixed automotive live target host."""

    return CAPTURED_TARGET


def live_scope() -> str:
    """Return the fixed automotive live target scope."""

    return CAPTURED_TARGET


def fuzzer_base_url() -> str:
    """Return the fixed automotive web base URL for fuzzer live tests."""

    return CAPTURED_BASE_URL


def discovered_http_state(base_url: str | None = None) -> CyberState:
    """Build a state with one known HTTP service for fuzzer/striker tests."""

    url = urlparse(base_url or fuzzer_base_url())
    host = url.hostname or live_target()
    port = url.port or (443 if url.scheme == "https" else 80)
    service_name = "https" if url.scheme == "https" else "http"
    state = base_state(
        mission_goal=f"Validate web tooling against {host}",
        target_scope=[live_scope()],
        mission_id="live-web",
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
                    "version": "Werkzeug httpd 3.1.8 (Python 3.10.12)" if service_name == "http" else "",
                    "banner": "",
                }
            },
        }
    }
    return state


def captured_web_findings(base_url: str | None = None) -> list[dict[str, Any]]:
    """Return normalized captured web findings from the captured automotive test."""

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


def captured_automotive_state(*, mission_id: str = "live-captured") -> CyberState:
    """Build a live-test state seeded with the precomputed automotive evidence."""

    state = base_state(
        mission_goal=f"Use the precomputed automotive evidence for a bounded live validation on {CAPTURED_TARGET}",
        target_scope=[live_scope(), CAPTURED_TARGET_IP],
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
        {
            "target": CAPTURED_BASE_URL,
            "tool": "web_content_enum",
            "status": "captured",
            "summary": "Loaded normalized gobuster findings from captured evidence.",
            "raw_stdout": CAPTURED_GOBUSTER_RAW["result"]["raw"]["stdout"],
        },
        {
            "target": CAPTURED_BASE_URL,
            "tool": "web_nikto_scan",
            "status": "captured",
            "summary": "Loaded normalized Nikto findings from captured evidence.",
            "raw_stdout": CAPTURED_NIKTO_RAW["result"]["raw"]["stdout"],
        },
    ]
    state["reconnaissance_runs"] = [
        {
            "target": CAPTURED_TARGET,
            "tool": "recon_service_probe",
            "status": "captured",
            "summary": "Loaded captured Nmap service/version evidence from the automotive testbed.",
            "raw_stdout": CAPTURED_NMAP_RAW,
        }
    ]
    state["research_cache"] = dict(CAPTURED_RESEARCH_CACHE)
    state["intelligence_findings"] = [dict(item) for item in CAPTURED_INTELLIGENCE_FINDINGS]
    return state


async def auto_detect_live_session() -> tuple[str, str] | None:
    """Pick the first live Metasploit session from the attackbox MCP server."""

    try:
        from agents.mcp import MCPServerStreamableHttp
    except Exception:
        return None

    url = ATTACKBOX_MCP_URL
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
        "summary": "Live test seed: use only bounded, approval-gated validation paths.",
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
            "doc_name": "live-fixture.md",
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
