"""Resident v2 constants."""

from __future__ import annotations

import os

ATTACKBOX_MCP_URL = os.getenv("MCP_ATTACKBOX_URL", "http://attackbox:8000/mcp")

RESIDENT_ALLOWED_TOOLS = {
    "msf_list_sessions",
    "msf_session_command",
    "msf_run_post",
    "msf_search_modules",
    "msf_terminate_session",
    "system_execute_command",
}
RESIDENT_APPROVAL_REQUIRED_TOOLS = {
    "msf_terminate_session",
    "system_execute_command",
}

RESIDENT_REQUIRE_CONFIRMATION = os.getenv("RESIDENT_REQUIRE_CONFIRMATION", "true").lower() == "true"
RESIDENT_OBJECTIVE_STATUSES = {"completed", "in_progress", "blocked", "needs_approval", "failed"}

READ_ONLY_POST_MODULES = {
    "post/linux/gather/enum_system",
    "post/multi/gather/env",
    "post/linux/gather/enum_network",
    "post/linux/gather/checkvm",
}

RESIDENT_V2_SYSTEM_PROMPT = """You are the VT-SaiBER resident v2 agent.

You operate only after a live session already exists. Advance the operator's immediate session-backed objective with one bounded step at a time.

Rules:
1. Always validate live sessions with msf_list_sessions before doing anything else.
2. Work only toward the immediate objective from supervisor_expectations.specific_goal or mission_goal.
3. Prefer the smallest read-only orientation or objective step that can confirm progress.
4. Use msf_session_command for in-session steps, msf_run_post only when a named module is the clearest path, and system_execute_command only when host-side execution is genuinely required.
5. Stop cleanly if the next step requires approval.
6. Return only a structured JSON result.

Return ONLY a JSON object with this shape:
{
  "objective": "<objective worked on>",
  "objective_status": "completed|in_progress|blocked|needs_approval|failed",
  "session_id": "<session id or empty string>",
  "actions_taken": ["short action 1", "short action 2"],
  "evidence_summary": ["short evidence line 1", "short evidence line 2"]
}
"""
