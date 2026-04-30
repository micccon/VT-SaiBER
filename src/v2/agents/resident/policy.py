"""Resident v2 approval policy."""

from __future__ import annotations

import re
from typing import Any

from src.utils.approval import derive_command_target, require_manual_approval
from src.v2.agents.resident.constants import READ_ONLY_POST_MODULES
from src.v2.contracts.execution import ToolCallInterception, ToolSpec
from src.v2.execution import ExecutionPolicy

READ_ONLY_SESSION_COMMAND_PATTERNS = (
    re.compile(r"^\s*id\s*$", re.IGNORECASE),
    re.compile(r"^\s*whoami\s*$", re.IGNORECASE),
    re.compile(r"^\s*uname(?:\s+-[^\s]+)?(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*hostname\s*$", re.IGNORECASE),
    re.compile(r"^\s*pwd\s*$", re.IGNORECASE),
    re.compile(r"^\s*env\s*$", re.IGNORECASE),
    re.compile(r"^\s*printenv\s*$", re.IGNORECASE),
    re.compile(r"^\s*ls(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*cat(?:\s+.+)$", re.IGNORECASE),
    re.compile(r"^\s*ip\s+addr(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*ip\s+route(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*ss(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*netstat(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*ps(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*sudo\s+-l(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*find(?:\s+.+)$", re.IGNORECASE),
    re.compile(r"^\s*grep(?:\s+.+)$", re.IGNORECASE),
    re.compile(r"^\s*crontab\s+-l(?:\s+.*)?$", re.IGNORECASE),
)


def _needs_approval_payload(**extra: Any) -> ToolCallInterception:
    """Return the normalized approval-block interception payload."""

    return ToolCallInterception(
        {
            "status": "aborted",
            "objective_status": "needs_approval",
            "message": "Execution blocked pending manual approval.",
            **extra,
        }
    )


def _is_read_only_session_command(command: str) -> bool:
    """Check whether a session command stays inside the read-only allowlist."""

    candidate = str(command or "").strip()
    return any(pattern.match(candidate) for pattern in READ_ONLY_SESSION_COMMAND_PATTERNS)


class ResidentExecutionPolicy(ExecutionPolicy):
    """Gate mutating or high-impact resident actions behind manual approval."""

    def __init__(self, *, require_confirmation: bool):
        self.require_confirmation = require_confirmation

    async def before_tool_call(
        self,
        tool: ToolSpec,
        arguments: dict[str, Any],
    ) -> ToolCallInterception | None:
        if tool.name == "msf_session_command":
            command = str(arguments.get("command", "") or "")
            if _is_read_only_session_command(command):
                return None
            if require_manual_approval(
                tool_name=tool.name,
                module_name=command,
                target=str(arguments.get("session_id") or "session"),
                enabled=self.require_confirmation,
            ):
                return None
            return _needs_approval_payload(command=command)

        if tool.name == "msf_run_post":
            module_name = str(arguments.get("module_name", "") or "").strip().lower()
            if module_name in READ_ONLY_POST_MODULES:
                return None
            session_id = ""
            if isinstance(arguments.get("options"), dict):
                session_id = str((arguments.get("options") or {}).get("SESSION") or "")
            if require_manual_approval(
                tool_name=tool.name,
                module_name=module_name,
                target=session_id or "session",
                enabled=self.require_confirmation,
            ):
                return None
            return _needs_approval_payload(module_name=module_name)

        if tool.name == "msf_terminate_session":
            if require_manual_approval(
                tool_name=tool.name,
                module_name="terminate_session",
                target=str(arguments.get("session_id") or "session"),
                enabled=self.require_confirmation,
            ):
                return None
            return _needs_approval_payload()

        if tool.name == "system_execute_command":
            command = str(arguments.get("command", "") or "")
            if require_manual_approval(
                tool_name=tool.name,
                module_name="shell-command",
                target=derive_command_target(command),
                action=command,
                enabled=self.require_confirmation,
            ):
                return None
            return _needs_approval_payload(command=command)

        return None
