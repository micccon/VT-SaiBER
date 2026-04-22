#!/usr/bin/env python3
"""
Focused Striker unit-style check for same-path retry blocking.

Run inside agents container:
    docker exec vt-saiber-agents python /app/tests/agent_tests/striker/test_striker_retry_guard.py
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
        return json.dumps({"status": "error", "tool": name, "kwargs": kwargs})

    async def _async_tool(**kwargs):
        return json.dumps(
            {
                "status": "error",
                "tool": name,
                "module": kwargs.get("module_name", ""),
                "options": kwargs.get("options", {}),
                "session_id_detected": None,
            }
        )

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
        advanced=False,
    )

    first_response = await wrapped_by_name["msf_run_exploit"].coroutine(
        module_name="multi/http/example",
        options={"RHOSTS": "automotive-testbed", "RPORT": 8000, "TARGETURI": "/console"},
        payload_name="python/meterpreter/bind_tcp",
        payload_options="LPORT=4444",
    )
    first_payload = json.loads(first_response)
    if first_payload.get("status") != "error":
        raise SystemExit(f"[FAIL] Expected first attempt to fail, got: {first_payload}")

    second_response = await wrapped_by_name["msf_run_exploit"].coroutine(
        module_name="multi/http/example",
        options={"RHOSTS": "automotive-testbed", "RPORT": 8000, "TARGETURI": "/console"},
        payload_name="python/meterpreter/bind_tcp",
        payload_options="LPORT=4445",
    )
    second_payload = json.loads(second_response)
    if second_payload.get("status") != "blocked":
        raise SystemExit(f"[FAIL] Expected same-path retry to be blocked, got: {second_payload}")

    third_response = await wrapped_by_name["msf_run_exploit"].coroutine(
        module_name="multi/http/example",
        options={"RHOSTS": "automotive-testbed", "RPORT": 8080, "TARGETURI": "/console"},
        payload_name="python/meterpreter/bind_tcp",
        payload_options="LPORT=4446",
    )
    third_payload = json.loads(third_response)
    if third_payload.get("status") != "blocked":
        raise SystemExit(f"[FAIL] Expected same module/target retry to be blocked, got: {third_payload}")

    print("[PASS] Failed exploit modules are blocked from immediate reuse against the same target in the current run.")


if __name__ == "__main__":
    asyncio.run(main())
