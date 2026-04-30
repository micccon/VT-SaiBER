from __future__ import annotations

import io

from src.runtime.approval import derive_command_target, require_manual_approval


class _InteractiveInput(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_derive_command_target_prefers_url():
    command = "curl -sS -I http://172.20.0.5:8000/login 2>&1 | head -20"
    assert derive_command_target(command) == "http://172.20.0.5:8000/login"


def test_require_manual_approval_displays_action_module_and_target():
    output = io.StringIO()
    approved = require_manual_approval(
        tool_name="system_execute_command",
        module_name="shell-command",
        target="http://172.20.0.5:8000/login",
        action="curl -sS http://172.20.0.5:8000/login",
        enabled=True,
        input_stream=_InteractiveInput("y\n"),
        output_stream=output,
    )

    rendered = output.getvalue()
    assert approved is True
    assert "[Approval] Tool: system_execute_command" in rendered
    assert "[Approval] Action: curl -sS http://172.20.0.5:8000/login" in rendered
    assert "[Approval] Module: shell-command" in rendered
    assert "[Approval] Target: http://172.20.0.5:8000/login" in rendered
