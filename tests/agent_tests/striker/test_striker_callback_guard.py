#!/usr/bin/env python3
"""
Focused Striker unit-style check for reverse-payload callback safety.

Run inside agents container:
    docker exec vt-saiber-agents python /app/tests/agent_tests/striker/test_striker_callback_guard.py
"""

import asyncio
import json
import sys
from pathlib import Path

from langchain_core.tools import StructuredTool

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

import src.agents.striker as striker_mod


def _make_tool(name: str) -> StructuredTool:
    def _sync_tool(**kwargs):
        return json.dumps({"status": "success", "tool": name, "kwargs": kwargs})

    async def _async_tool(**kwargs):
        return json.dumps({"status": "success", "tool": name, "kwargs": kwargs})

    return StructuredTool.from_function(
        func=_sync_tool,
        coroutine=_async_tool,
        name=name,
        description=f"Mock tool: {name}",
    )


async def main() -> None:
    agent = striker_mod.StrikerAgent()
    agent.require_confirmation = False

    wrapped = agent._wrap_tools(
        [
            _make_tool("msf_get_module_options"),
            _make_tool("msf_run_exploit"),
        ]
    )
    wrapped_by_name = {tool.name: tool for tool in wrapped}

    await wrapped_by_name["msf_get_module_options"].coroutine(
        module_type="exploit",
        module_name="multi/http/example",
        search="",
        advanced=True,
    )

    invalid_hosts = ["127.0.0.1", "localhost", "0.0.0.0"]
    for host in invalid_hosts:
        response = await wrapped_by_name["msf_run_exploit"].coroutine(
            module_name="multi/http/example",
            options={"RHOSTS": "automotive-testbed", "RPORT": "8000"},
            payload_name="python/meterpreter/reverse_tcp",
            payload_options=f"LHOST={host},LPORT=4444",
        )
        payload = json.loads(response)
        if payload.get("status") != "blocked":
            raise SystemExit(f"[FAIL] Expected blocked status for LHOST={host}, got: {payload}")

    print("[PASS] Reverse payload callback guard blocked invalid loopback/unspecified LHOST values.")


if __name__ == "__main__":
    asyncio.run(main())
