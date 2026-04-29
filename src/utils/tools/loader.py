"""Framework-neutral attackbox tool loading, schema conversion, and execution helpers."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

from src.utils.parsers import normalize_tool_result
from src.utils.tools.models import RuntimeTool


class RuntimeToolError(RuntimeError):
    """Raised when a runtime tool has no callable executor."""


def _clean_json_schema(value: Any) -> Any:
    """Strip noisy schema fields and make OpenAI function schemas stricter by default."""

    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}
        for key, item in value.items():
            if key in {"title"}:
                continue
            cleaned[key] = _clean_json_schema(item)
        if cleaned.get("type") == "object" and "additionalProperties" not in cleaned:
            cleaned["additionalProperties"] = False
        return cleaned

    if isinstance(value, list):
        return [_clean_json_schema(item) for item in value]

    return value


async def load_filtered_tools(allowed_tools: Iterable[str]) -> List[RuntimeTool]:
    """Load the current MCP tool inventory and apply the agent allowlist."""

    from src.mcp.mcp_tool_bridge import get_mcp_bridge

    bridge = await get_mcp_bridge()
    return bridge.get_tools_for_agent(set(allowed_tools))


def find_tool(tools: Iterable[RuntimeTool], *names: str) -> Optional[RuntimeTool]:
    """Find the first tool whose name matches one of the provided candidates."""

    candidates = {name for name in names if name}
    for tool in tools:
        if tool.name in candidates:
            return tool
    return None


async def invoke_tool(tool: RuntimeTool, **kwargs: Any) -> Any:
    """Invoke the underlying MCP-backed executor for a runtime tool."""

    if tool.executor is None:
        raise RuntimeToolError(f"Tool {tool.name} has no callable executor")
    return await tool.executor(**kwargs)


async def call_tool(tool: RuntimeTool, **kwargs: Any) -> Dict[str, Any]:
    """Invoke a tool and force the result into the normalized dict payload shape."""

    raw = await invoke_tool(tool, **kwargs)
    normalized = normalize_tool_payload(raw, tool_name=tool.name, invocation=kwargs)
    if isinstance(normalized, dict):
        return normalized
    return {"status": "error", "summary": f"Tool {tool.name} returned a non-JSON payload", "raw": raw}


def tool_names(tools: Iterable[RuntimeTool]) -> set[str]:
    """Return the set of tool names in the iterable."""

    return {tool.name for tool in tools}


def build_openai_tools(tools: Iterable[RuntimeTool]) -> List[Dict[str, Any]]:
    """Convert runtime tools into OpenAI-compatible tool definitions."""

    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or tool.name,
                "parameters": _clean_json_schema(tool.input_schema or {"type": "object", "properties": {}}),
            },
        }
        for tool in tools
    ]


def parse_tool_arguments(raw_arguments: str | None) -> Dict[str, Any]:
    """Decode tool-call arguments from the model into a JSON object."""

    candidate = str(raw_arguments or "").strip()
    if not candidate:
        return {}

    parsed = json.loads(candidate)
    if isinstance(parsed, dict):
        return parsed
    raise ValueError("Tool arguments must decode to an object")


def normalize_tool_payload(raw: Any, *, tool_name: str, invocation: dict[str, Any]) -> dict[str, Any] | Any:
    """Normalize varied tool outputs into a shared transcript-friendly payload."""

    normalized = normalize_tool_result(raw)
    if normalized:
        normalized.setdefault("invocation", invocation)
        return normalized

    if isinstance(raw, dict):
        payload = dict(raw)
        payload.setdefault("invocation", invocation)
        return payload

    if isinstance(raw, list):
        return {
            "status": "success",
            "result": raw,
            "tool": tool_name,
            "invocation": invocation,
        }

    if isinstance(raw, str):
        candidate = raw.strip()
        if candidate:
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                parsed.setdefault("invocation", invocation)
                return parsed
            if parsed is not None:
                return {
                    "status": "success",
                    "result": parsed,
                    "tool": tool_name,
                    "invocation": invocation,
                }
        return {
            "status": "success",
            "output": raw,
            "tool": tool_name,
            "invocation": invocation,
        }

    return {
        "status": "success",
        "result": raw,
        "tool": tool_name,
        "invocation": invocation,
    }


def serialize_tool_result(payload: Any) -> str:
    """Serialize a normalized tool result back into the model conversation."""

    if isinstance(payload, str):
        return payload
    return json.dumps(payload, indent=2, default=str)
