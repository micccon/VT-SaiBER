"""
Helpers for converting MCP/LangChain tools into OpenAI-compatible schemas.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List

from langchain_core.tools import StructuredTool


def _clean_json_schema(value: Any) -> Any:
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


def _tool_parameters(tool: StructuredTool) -> Dict[str, Any]:
    schema_model = getattr(tool, "args_schema", None)
    if schema_model is None:
        return {"type": "object", "properties": {}, "additionalProperties": False}

    if hasattr(schema_model, "model_json_schema"):
        return _clean_json_schema(schema_model.model_json_schema())

    if hasattr(schema_model, "schema"):
        return _clean_json_schema(schema_model.schema())

    return {"type": "object", "properties": {}, "additionalProperties": False}


def build_openai_tools(tools: Iterable[StructuredTool]) -> List[Dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or tool.name,
                "parameters": _tool_parameters(tool),
            },
        }
        for tool in tools
    ]


def parse_tool_arguments(raw_arguments: str | None) -> Dict[str, Any]:
    candidate = str(raw_arguments or "").strip()
    if not candidate:
        return {}

    parsed = json.loads(candidate)
    if isinstance(parsed, dict):
        return parsed
    raise ValueError("Tool arguments must decode to an object")


def serialize_tool_result(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, indent=2, default=str)
