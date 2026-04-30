"""Minimal approval policy for lean Striker."""

from __future__ import annotations

from src.runtime.approval import derive_command_target, require_manual_approval
from src.runtime.contracts import ToolSpec
from src.runtime.execution import ExecutionPolicy


def _extract_target(arguments: dict[str, object], tool_name: str) -> str:
    """Resolve the best-effort approval target from tool arguments."""

    options = arguments.get("options")
    target = ""
    if isinstance(options, dict):
        target = str(options.get("RHOSTS") or options.get("RHOST") or options.get("TARGET") or "").strip()
    if target:
        return target
    if tool_name == "system_execute_command":
        command = str(arguments.get("command") or "").strip()
        derived = derive_command_target(command)
        if derived:
            return derived
    return str(arguments.get("target") or arguments.get("url") or "unknown")


class StrikerExecutionPolicy(ExecutionPolicy):
    """Lean Striker guardrail surface: approval only."""

    def __init__(self, *, require_confirmation: bool, max_attempts: int):
        self.require_confirmation = require_confirmation
        self.max_attempts = max_attempts

    async def approve_tool_call(self, tool: ToolSpec, arguments: dict[str, object]) -> bool:
        """Require manual approval only for tools marked approval-required."""

        if not tool.approval_required:
            return True

        module_label = str(
            arguments.get("module_name")
            or arguments.get("service")
            or arguments.get("additional_args")
            or ""
        ).strip()
        if tool.name == "system_execute_command":
            module_label = "shell-command"

        return require_manual_approval(
            tool_name=tool.name,
            module_name=module_label,
            target=_extract_target(arguments, tool.name),
            action=str(arguments.get("command") or ""),
            enabled=self.require_confirmation,
        )
