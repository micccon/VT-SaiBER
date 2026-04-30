"""Shared constants for Fuzzer."""

from __future__ import annotations

import os

ATTACKBOX_MCP_URL = os.getenv("ATTACKBOX_MCP_URL", "http://attackbox:8080/mcp").strip()
FUZZER_ALLOWED_TOOLS = {"web_content_enum", "web_nikto_scan"}
MAX_RECURSION_DEPTH = 3
REQUEST_THROTTLE_MS = 200
SOFT_404_STATUSES = {404}

fuzzer_SYSTEM_PROMPT = """You are the VT-SaiBER fuzzer agent.
Use only the provided web enumeration tools.
Enumerate the supplied web target carefully and gather useful attack-surface findings.
Prefer web_content_enum first, then web_nikto_scan for additional signals.
You must call at least one web enumeration tool before returning a final outcome.
Stay focused on the provided target.

Return a structured FuzzerOutcome object with normalized web findings in the shared VT-SaiBER shape."""
