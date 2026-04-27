"""
Single attackbox MCP bridge for VT-SaiBER agents.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import AsyncExitStack
from typing import Any, Dict, List, Optional, Set

from langchain_core.tools import StructuredTool
from mcp import ClientSession
from pydantic import BaseModel, Field, create_model

logger = logging.getLogger(__name__)


def _load_streamable_http_client():
    """
    Support the MCP Python SDK naming variants for Streamable HTTP.
    """
    try:
        from mcp.client.streamable_http import streamablehttp_client

        return streamablehttp_client
    except ImportError:
        pass

    try:
        from mcp.client.streamable_http import streamable_http_client

        return streamable_http_client
    except ImportError as exc:
        raise RuntimeError(
            "Streamable HTTP transport is unavailable in the installed MCP SDK. "
            "Upgrade the `mcp` package to a version that provides "
            "`mcp.client.streamable_http`."
        ) from exc


class MCPToolBridge:
    """
    Bridge between the agents and the unified attackbox MCP server.
    """

    def __init__(self) -> None:
        self.exit_stack = AsyncExitStack()
        self.session: ClientSession | None = None
        self.owner_loop: asyncio.AbstractEventLoop | None = None
        self.closed = False
        self.all_tools: List[StructuredTool] = []
        self._tool_cache: Dict[str, StructuredTool] = {}

    async def connect(self, url: str) -> None:
        if not url:
            raise ValueError("ATTACKBOX_MCP_URL is empty")

        candidate = url.strip().rstrip("/")
        logger.info("Connecting to attackbox MCP at %s", candidate)

        transport_client = _load_streamable_http_client()
        transport = await self.exit_stack.enter_async_context(transport_client(candidate))

        if isinstance(transport, tuple):
            if len(transport) >= 2:
                read, write = transport[0], transport[1]
            else:
                raise RuntimeError("Unexpected Streamable HTTP transport tuple returned by MCP SDK")
        else:
            raise RuntimeError("Unexpected Streamable HTTP transport object returned by MCP SDK")

        self.session = await self.exit_stack.enter_async_context(ClientSession(read, write))
        await self.session.initialize()

        tools_result = await self.session.list_tools()
        self.all_tools = [self._mcp_to_langchain(tool_def) for tool_def in tools_result.tools]
        self._tool_cache = {tool.name: tool for tool in self.all_tools}
        logger.info("Attackbox MCP connected with %d tools", len(self.all_tools))

    def _mcp_to_langchain(self, mcp_tool: Any) -> StructuredTool:
        input_schema = getattr(mcp_tool, "inputSchema", {}) or {}
        fields: Dict[str, Any] = {}
        required = set(input_schema.get("required", []) or [])
        defaults: Dict[str, Any] = {}

        for prop_name, prop_schema in (input_schema.get("properties", {}) or {}).items():
            field_type = self._json_type_to_python(prop_schema.get("type", "string"))
            has_default = "default" in prop_schema
            default_value = prop_schema.get("default")
            field_required = (prop_name in required) and (not has_default)
            field_description = prop_schema.get("description", "")

            if field_required:
                fields[prop_name] = (field_type, Field(description=field_description))
            else:
                effective_default = default_value if has_default else None
                fields[prop_name] = (
                    Optional[field_type],
                    Field(default=effective_default, description=field_description),
                )
                if has_default:
                    defaults[prop_name] = default_value

        if fields:
            ArgsSchema = create_model(f"{mcp_tool.name}_args", **fields)
        else:
            ArgsSchema = create_model(f"{mcp_tool.name}_args", __base__=BaseModel)

        async def execute_tool(**kwargs: Any) -> str:
            if self.session is None:
                raise RuntimeError("Attackbox MCP session is not connected")

            cleaned_kwargs: Dict[str, Any] = {}
            for key, value in kwargs.items():
                if value is None:
                    if key in defaults:
                        cleaned_kwargs[key] = defaults[key]
                    continue
                cleaned_kwargs[key] = value

            logger.info("[attackbox] Executing %s with args: %s", mcp_tool.name, cleaned_kwargs)
            result = await self.session.call_tool(mcp_tool.name, cleaned_kwargs)
            return self._serialize_result(result)

        return StructuredTool(
            name=mcp_tool.name,
            description=getattr(mcp_tool, "description", "") or mcp_tool.name,
            func=execute_tool,
            coroutine=execute_tool,
            args_schema=ArgsSchema,
        )

    def _serialize_result(self, result: Any) -> str:
        structured = getattr(result, "structuredContent", None)
        if structured is not None:
            return json.dumps(structured, indent=2, default=str)

        content_blocks = getattr(result, "content", None)
        if content_blocks:
            text_parts: List[str] = []
            for block in content_blocks:
                text = getattr(block, "text", None)
                if text is not None:
                    text_parts.append(text)
            combined = "\n".join(text_parts).strip()
            if combined:
                try:
                    parsed = json.loads(combined)
                    return json.dumps(parsed, indent=2, default=str)
                except json.JSONDecodeError:
                    return combined

        return "{}"

    def _json_type_to_python(self, json_type: str) -> type:
        return {
            "string": str,
            "integer": int,
            "number": float,
            "boolean": bool,
            "object": dict,
            "array": list,
        }.get(json_type, str)

    def get_tools_for_agent(self, allowed_tools: Optional[Set[str]] = None) -> List[StructuredTool]:
        if allowed_tools is None:
            logger.warning("get_tools_for_agent called with no allowlist; returning no tools")
            return []
        return [tool for tool in self.all_tools if tool.name in allowed_tools]

    async def disconnect(self) -> None:
        if self.closed:
            return
        try:
            await self.exit_stack.aclose()
        finally:
            self.session = None
            self.all_tools.clear()
            self._tool_cache.clear()
            self.closed = True
            logger.info("Disconnected from attackbox MCP")


_bridge: MCPToolBridge | None = None


async def get_mcp_bridge() -> MCPToolBridge:
    global _bridge
    current_loop = asyncio.get_running_loop()
    if _bridge is not None:
        if getattr(_bridge, "closed", False):
            _bridge = None
        elif getattr(_bridge, "owner_loop", None) is not current_loop:
            logger.warning("Discarding stale attackbox bridge bound to a different event loop")
            _bridge = None

    if _bridge is None:
        _bridge = MCPToolBridge()
        _bridge.owner_loop = current_loop
        attackbox_url = os.getenv("ATTACKBOX_MCP_URL", "http://attackbox:8080/mcp")
        await _bridge.connect(attackbox_url)
    return _bridge


async def reset_mcp_bridge() -> None:
    global _bridge
    bridge = _bridge
    _bridge = None
    if bridge is None:
        return
    try:
        await bridge.disconnect()
    except Exception as exc:
        logger.warning("Error while resetting attackbox bridge: %s", exc)
