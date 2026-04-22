#!/usr/bin/env python3
"""
Focused Striker unit-style check for system prompt guardrails.

Run inside agents container:
    docker exec vt-saiber-agents python /app/tests/agent_tests/striker/test_striker_prompt_guard.py
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

import src.agents.striker as striker_mod


def main() -> None:
    prompt = striker_mod.StrikerAgent().system_prompt
    required_snippets = [
        "Search with narrow evidence-based terms derived from the target technology",
        "Match the Metasploit module family to the task",
        "Path Selection Rules:",
        "Option Selection Rules:",
        "Failure Handling Rules:",
        "Prefer the minimum viable option set",
        "Do not retry the same exploit path with lightly edited guessed options",
    ]

    missing = [snippet for snippet in required_snippets if snippet not in prompt]
    if missing:
        raise SystemExit(f"[FAIL] Missing prompt guidance: {missing}")

    print("[PASS] Striker system prompt includes the expected general decision guardrails.")


if __name__ == "__main__":
    main()
