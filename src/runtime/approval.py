"""Shared approval helpers for guarded runtime actions."""

from __future__ import annotations

import re
import shlex
import sys
from typing import TextIO

_URL_RE = re.compile(r"https?://[^\s\"']+")
_HOST_TOKEN_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9][A-Za-z0-9.-]*)(?::\d+)?$")


def derive_command_target(command: str) -> str:
    """Best-effort target extraction for shell-command approval prompts."""

    raw_command = str(command or "").strip()
    if not raw_command:
        return "unknown"

    url_match = _URL_RE.search(raw_command)
    if url_match:
        return url_match.group(0)

    try:
        tokens = shlex.split(raw_command)
    except ValueError:
        tokens = raw_command.split()

    for idx, token in enumerate(tokens[:-1]):
        if token in {"-u", "--url", "-h", "--host", "--hostname"}:
            candidate = tokens[idx + 1].strip()
            if candidate:
                return candidate

    skipped = {
        "curl",
        "echo",
        "head",
        "cat",
        "grep",
        "sed",
        "awk",
        "sqlmap",
        "nikto",
        "nmap",
        "bash",
        "sh",
    }
    for token in tokens:
        candidate = token.strip()
        if not candidate or candidate.startswith("-") or candidate in {"&&", "||", "|", ";"}:
            continue
        if candidate in skipped:
            continue
        if _HOST_TOKEN_RE.match(candidate):
            return candidate

    return "unknown"


def require_manual_approval(
    tool_name: str,
    module_name: str,
    target: str,
    action: str = "",
    enabled: bool = True,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> bool:
    """Prompt for manual approval when enabled."""

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
    if action:
        print(f"[Approval] Action: {action}", file=out_stream)
    print(f"[Approval] Module: {module_name or 'unknown'}", file=out_stream)
    print(f"[Approval] Target: {target or 'unknown'}", file=out_stream)
    print("Approve execution? [y/N]: ", end="", file=out_stream, flush=True)

    decision = in_stream.readline().strip().lower()
    return decision in {"y", "yes"}
