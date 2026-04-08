"""
Parsing helpers used by orchestration components.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict


def extract_json_payload(text: str) -> Dict[str, Any]:
    """
    Extract a JSON object from raw model text output.
    Supports plain JSON or fenced markdown blocks.
    """
    candidate = (text or "").strip()
    if not candidate:
        raise ValueError("Empty model response")

    fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", candidate)
    if fenced:
        candidate = fenced.group(1).strip()

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        parsed = _extract_first_object(candidate)

    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object")
    return parsed


def _extract_first_object(text: str) -> Any:
    start = text.find("{")
    if start < 0:
        raise ValueError("No JSON object found")

    depth = 0
    for idx in range(start, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : idx + 1])
    raise ValueError("Malformed JSON object")


def to_jsonable(value: Any) -> Any:
    """
    Convert Pydantic or dataclass-like objects into plain JSONable structures.
    """
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    return value


def normalize_tool_result(raw: Any) -> Dict[str, Any]:
    """
    Normalize tool results into a plain dictionary when possible.
    Accepts direct dicts, JSON strings, and common {"result": ...} envelopes.
    """
    payload = raw

    if isinstance(payload, str):
        candidate = payload.strip()
        if not candidate:
            return {}
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            try:
                payload = _extract_first_object(candidate)
            except ValueError:
                return {}

    if not isinstance(payload, dict):
        return {}

    nested = payload.get("result")
    if len(payload) == 1 and isinstance(nested, dict):
        return nested

    return payload


def metasploit_module_key(module_type: Any, module_name: Any) -> str:
    """
    Build a stable lowercase key for Metasploit module bookkeeping.
    """
    normalized_name = str(module_name or "").strip().lower()
    if not normalized_name:
        return ""

    normalized_type = str(module_type or "").strip().lower()
    if not normalized_type:
        return normalized_name

    return f"{normalized_type}:{normalized_name}"
