from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ResearchEvidence:
    source_type: str
    identifier: str
    title: str
    reference: str
    snippet: str
    score: float | None = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LibrarianDependencyStatus:
    statuses: Dict[str, str] = field(default_factory=dict)
    degraded_reasons: List[str] = field(default_factory=list)

    def mark(self, dependency: str, status: str) -> None:
        self.statuses[str(dependency)] = str(status)

    def add_reason(self, reason: str) -> None:
        cleaned = str(reason).strip()
        if cleaned and cleaned not in self.degraded_reasons:
            self.degraded_reasons.append(cleaned)
