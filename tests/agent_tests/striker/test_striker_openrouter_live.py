#!/usr/bin/env python3
"""
Striker OpenRouter Live Smoke Test
==================================
Runs the real striker_node with OpenRouter and real MCP bridge/tool discovery.

Safety defaults:
- Uses STRIKER_REQUIRE_CONFIRMATION=true
So exploit-execution tool calls are blocked in non-interactive runs.

Run inside agents container:
  docker exec \
    -e OPENROUTER_API_KEY=... \
    -e LLM_CLIENT=openrouter \
    -e LLM_MODEL=meta-llama/llama-3.1-8b-instruct:free \
    -e STRIKER_REQUIRE_CONFIRMATION=true \
    vt-saiber-agents \
    python /app/tests/agent_tests/test_striker_openrouter_live.py
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, "/app")

from src.agents.striker import striker_node


def _as_dict(item):
    if hasattr(item, "model_dump"):
        return item.model_dump()
    if isinstance(item, dict):
        return item
    return {"value": str(item)}


def _mock_state():
    return {
        "mission_goal": "Gain initial access to automotive-testbed",
        "mission_id": "live-striker-openrouter-smoke",
        "mission_status": "active",
        "current_agent": "striker",
        "next_agent": None,
        "iteration_count": 0,
        "target_scope": ["172.20.0.0/16", "automotive-testbed"],
        "discovered_targets": {
            "automotive-testbed": {
                "ip_address": "automotive-testbed",
                "os_guess": "Linux (Ubuntu 20.04)",
                "ports": [22, 8000, 8080],
                "services": {
                    "22": {
                        "service_name": "ssh",
                        "version": "OpenSSH 8.2p1 Ubuntu",
                        "banner": "SSH-2.0-OpenSSH_8.2p1",
                    },
                    "8000": {
                        "service_name": "http",
                        "version": "Python/3.8 BaseHTTPServer",
                        "banner": "",
                    },
                    "8080": {
                        "service_name": "http",
                        "version": "Werkzeug/2.0.1 Python/3.8",
                        "banner": "",
                    },
                },
                "vulns": [],
            }
        },
        "web_findings": [
            {"path": "/login", "status_code": 200, "is_interesting": True},
            {"path": "/api/users", "status_code": 200, "is_interesting": True},
        ],
        "research_cache": {
            "OpenSSH 8.2p1": "Brute-force or credential-based path likely.",
            "Werkzeug 2.0.1": "Debug console issues possible if debug mode enabled.",
        },
        "osint_findings": [
            {
                "source": "NVD",
                "cve": "CVE-2016-10516",
                "description": "Werkzeug debugger issue in debug mode.",
                "data": {"msf_module": ""},
            }
        ],
        "active_sessions": {},
        "exploited_services": [],
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }


async def main():
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        print("[FAIL] OPENROUTER_API_KEY is not set.")
        raise SystemExit(1)

    # Force safe defaults for this smoke test.
    os.environ["LLM_CLIENT"] = os.getenv("LLM_CLIENT", "openrouter")
    os.environ["LLM_MODEL"] = os.getenv("LLM_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
    os.environ["STRIKER_REQUIRE_CONFIRMATION"] = os.getenv("STRIKER_REQUIRE_CONFIRMATION", "true")

    print("=" * 68)
    print("Striker OpenRouter Live Smoke Test")
    print("=" * 68)
    print(f"LLM_CLIENT={os.getenv('LLM_CLIENT')}")
    print(f"LLM_MODEL={os.getenv('LLM_MODEL')}")
    print(f"STRIKER_REQUIRE_CONFIRMATION={os.getenv('STRIKER_REQUIRE_CONFIRMATION')}")

    state = _mock_state()
    out = await striker_node(state)

    errors = [_as_dict(e) for e in out.get("errors", [])]
    if errors:
        print("\nErrors:")
        print(json.dumps(errors, indent=2))
        # Fail only on infra/config errors for smoke test.
        err_types = {e.get("error_type", "") for e in errors}
        if {"LLMConfigError", "ToolError"} & err_types:
            print("[FAIL] Live smoke test failed due to LLM/tool infra error.")
            raise SystemExit(1)

    print("\nSummary:")
    print(f"- iteration_count: {out.get('iteration_count')}")
    print(f"- exploited_services entries: {len(out.get('exploited_services', []))}")
    print(f"- active_sessions keys: {list((out.get('active_sessions') or {}).keys())}")
    print(f"- critical_findings: {out.get('critical_findings', [])}")
    print("[PASS] Striker live smoke test completed.")


if __name__ == "__main__":
    asyncio.run(main())
