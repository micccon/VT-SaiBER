"""
Shared runtime data models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable


@dataclass
class RuntimeTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    executor: Callable[..., Awaitable[Any]]
    defaults: dict[str, Any] = field(default_factory=dict)
