"""CyberState mapping for Fuzzer v2."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.state.models import AgentError, AgentLogEntry
from src.utils.agent_parsers import dedupe_web_findings
from src.v2.agents.fuzzer.constants import MAX_RECURSION_DEPTH, REQUEST_THROTTLE_MS
from src.v2.agents.fuzzer.outcome import FuzzerOutcome
from src.v2.contracts.execution import ExecutionResult


def _fallback_finding(base_url: str) -> dict[str, Any]:
    """Build the minimal fallback finding when the model returns none."""

    return {
        "url": f"{base_url}/",
        "path": "/",
        "status_code": 200,
        "content_length": 0,
        "content_type": "unknown",
        "is_api_endpoint": False,
        "is_interesting": False,
        "discovery_depth": 0,
        "scan_policy": {
            "methods": ["GET", "HEAD"],
            "max_depth": MAX_RECURSION_DEPTH,
            "request_throttle_ms": REQUEST_THROTTLE_MS,
            "soft_404_detection": True,
        },
        "rationale": "Fallback finding while MCP scan is unavailable",
    }


def map_execution_result_to_state(
    state: CyberState,
    *,
    agent_name: str,
    context: str,
    result: ExecutionResult[FuzzerOutcome],
) -> dict[str, Any]:
    """Convert a Fuzzer v2 execution result into CyberState updates."""

    outcome = result.outcome
    findings = [finding.model_dump() for finding in outcome.web_findings]
    findings = dedupe_web_findings(findings)[:100]
    if not findings:
        findings = [_fallback_finding(outcome.base_url)]

    reasoning = "\n\n".join(
        item for item in [outcome.operator_summary.strip(), str(outcome.stop_reason or "").strip()] if item
    ).strip() or context
    return {
        "current_agent": agent_name,
        "iteration_count": int(state.get("iteration_count", 0)) + 1,
        "web_findings": findings,
        "agent_log": [
            AgentLogEntry(
                agent=agent_name,
                action="web_enumeration",
                target=outcome.base_url,
                findings={
                    "findings_count": len(findings),
                    "max_depth": MAX_RECURSION_DEPTH,
                    "request_throttle_ms": REQUEST_THROTTLE_MS,
                    "soft_404_detection": True,
                },
                reasoning=reasoning,
            )
        ],
    }

