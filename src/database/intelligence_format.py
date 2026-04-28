from __future__ import annotations

import json
from typing import Any, Dict


def build_intelligence_embedding_text(title: str, description: str, payload: Dict[str, Any]) -> str:
    return "\n".join(
        part
        for part in [
            str(title or "").strip(),
            str(description or "").strip(),
            json.dumps(payload or {}, default=str),
        ]
        if part
    )
