"""
Shared approval helpers for guarded agent actions.
"""

from __future__ import annotations

import sys
from typing import TextIO


def require_manual_approval(
    tool_name: str,
    module_name: str,
    target: str,
    enabled: bool = True,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> bool:
    """
    Prompt for manual approval when enabled.
    Denies by default when running non-interactively.
    """
    if not enabled:
        return True

    in_stream = input_stream or sys.stdin
    out_stream = output_stream or sys.stdout

    if in_stream is None or not getattr(in_stream, "isatty", lambda: False)():
        print(
            "[Approval] Execution blocked: manual approval required, "
            "but stdin is non-interactive.",
            file=out_stream,
        )
        return False

    print("\n[Approval] Manual approval required", file=out_stream)
    print(f"[Approval] Tool: {tool_name}", file=out_stream)
    print(f"[Approval] Module: {module_name or 'unknown'}", file=out_stream)
    print(f"[Approval] Target: {target or 'unknown'}", file=out_stream)
    print("Approve execution? [y/N]: ", end="", file=out_stream, flush=True)

    decision = in_stream.readline().strip().lower()
    return decision in {"y", "yes"}
