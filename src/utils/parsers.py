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
