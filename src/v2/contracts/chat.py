"""Typed contracts for the v2 chat/synthesis lane."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from src.v2.contracts.execution import ModelConfig

TOutcome = TypeVar("TOutcome")


@dataclass(frozen=True)
class ChatSynthesisSpec(Generic[TOutcome]):
    """Declarative description of one non-tool v2 synthesis run."""

    agent_name: str
    instructions: str
    model: ModelConfig
    output_type: type[TOutcome]


@dataclass
class ChatSynthesisResult(Generic[TOutcome]):
    """Typed result returned by the v2 chat/synthesis runner."""

    outcome: TOutcome
    raw_result: Any = None
    raw_text: str = ""
