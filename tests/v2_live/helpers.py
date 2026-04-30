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
from src.v2.agents.scout.constants import ATTACKBOX_MCP_URL


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
    host = os.getenv("LIVE_FUZZER_TARGET") or os.getenv("TARGET_HOST") or live_target()
    port = int((os.getenv("LIVE_FUZZER_PORT") or "80").strip() or "80")
    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{host}" if port in {80, 443} else f"{scheme}://{host}:{port}"


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
