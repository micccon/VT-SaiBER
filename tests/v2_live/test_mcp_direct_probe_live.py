"""Direct attackbox MCP probe tests with no LLM dependency."""

from __future__ import annotations

from typing import Any

import pytest

from src.v2.agents.fuzzer.constants import FUZZER_ALLOWED_TOOLS
from src.v2.agents.resident.constants import RESIDENT_ALLOWED_TOOLS
from src.v2.agents.scout.constants import ATTACKBOX_MCP_URL, SCOUT_ALLOWED_TOOLS
from src.v2.agents.striker.constants import STRIKER_ALLOWED_TOOLS
from src.v2.execution.runner import _normalize_mcp_call_result
from tests.v2_live.helpers import CAPTURED_BASE_URL, CAPTURED_TARGET, step

pytestmark = pytest.mark.live

EXPECTED_ATTACKBOX_TOOLS = {
    *SCOUT_ALLOWED_TOOLS,
    *FUZZER_ALLOWED_TOOLS,
    *STRIKER_ALLOWED_TOOLS,
    *RESIDENT_ALLOWED_TOOLS,
}

SAFE_TOOL_CALLS: dict[str, dict[str, Any]] = {
    "msf_list_sessions": {},
    "msf_search_modules": {"search_term": "ssh", "limit": 3},
    "recon_port_scan": {"target": "127.0.0.1", "ports": "22,80,443", "additional_args": "-T4"},
    "recon_service_probe": {"target": CAPTURED_TARGET, "ports": "22,8000,8080", "additional_args": "-T4"},
    "web_http_request": {"url": CAPTURED_BASE_URL, "method": "GET"},
}


def _tool_name(tool_def: Any) -> str:
    if isinstance(tool_def, dict):
        return str(tool_def.get("name") or "")
    return str(getattr(tool_def, "name", "") or "")


def _tool_schema(tool_def: Any) -> dict[str, Any]:
    if isinstance(tool_def, dict):
        schema = tool_def.get("inputSchema") or tool_def.get("input_schema") or {}
    else:
        schema = getattr(tool_def, "inputSchema", None) or getattr(tool_def, "input_schema", None) or {}
    return schema if isinstance(schema, dict) else {}


def _unwrap_tool_payload(payload: Any) -> dict[str, Any]:
    """Unwrap direct MCP envelopes that nest normalized tool output under result."""

    if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
        return payload["result"]
    return payload if isinstance(payload, dict) else {}


async def _connect_attackbox():
    pytest.importorskip("agents")
    from agents.mcp import MCPServerStreamableHttp

    server = MCPServerStreamableHttp(
        name="attackbox",
        params={"url": ATTACKBOX_MCP_URL},
        cache_tools_list=False,
    )
    return server


@pytest.mark.asyncio
async def test_attackbox_mcp_advertises_all_v2_tools():
    """Verify every v2-required MCP tool is advertised by attackbox."""

    server = await _connect_attackbox()
    async with server:
        tools_result = await server.list_tools()
        tools = getattr(tools_result, "tools", tools_result) or []
        tool_names = {_tool_name(tool) for tool in tools}
        schemas = {name: _tool_schema(tool) for tool in tools if (name := _tool_name(tool))}

    missing = sorted(EXPECTED_ATTACKBOX_TOOLS - tool_names)
    step(f"Attackbox MCP advertised {len(tool_names)} tool(s): {sorted(tool_names)}")
    step(f"V2 expected tools present: {sorted(EXPECTED_ATTACKBOX_TOOLS - set(missing))}")
    if missing:
        pytest.fail(f"Attackbox MCP missing v2-required tools: {missing}")

    for name in sorted(EXPECTED_ATTACKBOX_TOOLS):
        step(f"MCP_SCHEMA {name}: {schemas.get(name, {})}")


@pytest.mark.asyncio
async def test_attackbox_mcp_safe_tools_are_callable():
    """Call a safe/read-only subset so MCP execution is proven without an LLM."""

    server = await _connect_attackbox()
    results: dict[str, Any] = {}
    async with server:
        tools_result = await server.list_tools()
        tool_names = {_tool_name(tool) for tool in (getattr(tools_result, "tools", tools_result) or [])}
        missing_safe = sorted(set(SAFE_TOOL_CALLS) - tool_names)
        if missing_safe:
            pytest.fail(f"Attackbox MCP missing safe probe tools: {missing_safe}")

        for tool_name, arguments in SAFE_TOOL_CALLS.items():
            step(f"MCP_CALL {tool_name}({arguments})")
            raw = await server.call_tool(tool_name, arguments)
            payload = _unwrap_tool_payload(_normalize_mcp_call_result(raw))
            results[tool_name] = payload
            status = payload.get("status")
            step(f"MCP_RESULT {tool_name}: status={status} payload={payload}")
            if status not in {"success", "error"}:
                pytest.fail(f"{tool_name} returned unexpected status {status!r}: {payload}")

    assert results["msf_list_sessions"]
