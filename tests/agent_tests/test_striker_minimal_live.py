"""
Minimal live Striker planning test.

This test feeds Striker only a tiny prebuilt state so we can tell whether
stalling is caused by the large captured context or by the first live model
call itself.

Run inside the agents container:
    docker exec vt-saiber-agents python3 -m pytest tests/agent_tests/test_striker_minimal_live.py -q -s
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytest.importorskip("mcp")

import src.agents.striker as striker_module
from src.config import get_runtime_config
from src.main import build_initial_state
from src.mcp.mcp_tool_bridge import get_mcp_bridge, reset_mcp_bridge
from src.state.cyber_state import CyberState
from src.utils.tools import RuntimeTool


pytestmark = pytest.mark.live


MINIMAL_TARGET = (os.getenv("LIVE_STRIKER_MINIMAL_TARGET") or "172.20.0.5").strip() or "172.20.0.5"
MINIMAL_STRIKER_TIMEOUT_SECONDS = int(
    (os.getenv("LIVE_STRIKER_TIMEOUT_SECONDS") or "180").strip() or "180"
)
LIVE_STRIKER_EXECUTE = (os.getenv("LIVE_STRIKER_EXECUTE") or "false").strip().lower() == "true"
LIVE_STRIKER_INTERACTIVE_APPROVAL = (
    os.getenv("LIVE_STRIKER_INTERACTIVE_APPROVAL") or "false"
).strip().lower() == "true"
TRACE_EVENTS: List[Dict[str, Any]] = []


def _step(message: str) -> None:
    print(f"[minimal-step] {message}", flush=True)


def _approval_mode_label() -> str:
    if LIVE_STRIKER_INTERACTIVE_APPROVAL:
        return "interactive approval"
    if LIVE_STRIKER_EXECUTE:
        return "auto-approve"
    return "planning-only"


def _safe_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _safe_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if hasattr(value, "model_dump"):
        return _safe_json(value.model_dump())
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass
    return value


def _trace(label: str, payload: Dict[str, Any]) -> None:
    print(f"[minimal-trace] {label}: {json.dumps(_safe_json(payload), default=str)}", flush=True)


def _result_preview(value: Any, max_chars: int = 4000) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(_safe_json(value), default=str, indent=2)
    return text[:max_chars] + ("...(truncated)" if len(text) > max_chars else "")


def _run(coro):
    async def _wrapped():
        try:
            return await coro
        finally:
            await reset_mcp_bridge()

    return asyncio.run(_wrapped())


def _mission_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"minimal-striker-{stamp}"


def _wrap_tool_with_trace(tool: RuntimeTool) -> RuntimeTool:
    async def traced_coroutine(**kwargs):
        call_id = len(TRACE_EVENTS) + 1
        event = {
            "id": call_id,
            "tool": tool.name,
            "args": kwargs,
            "status": "started",
        }
        TRACE_EVENTS.append(event)
        _trace("TOOL_START", {"id": call_id, "tool": tool.name, "args": kwargs})
        started = asyncio.get_running_loop().time()
        try:
            result = await tool.executor(**kwargs)
            elapsed = asyncio.get_running_loop().time() - started
            event["status"] = "ok"
            event["elapsed_s"] = round(elapsed, 3)
            event["result_preview"] = _result_preview(result)
            _trace("TOOL_END", {"id": call_id, "tool": tool.name, "status": "ok", "elapsed_s": round(elapsed, 3)})
            print(f"[minimal-trace] TOOL_RESULT[{call_id}]:\n{_result_preview(result)}", flush=True)
            return result
        except Exception as exc:
            elapsed = asyncio.get_running_loop().time() - started
            event["status"] = "error"
            event["elapsed_s"] = round(elapsed, 3)
            event["error"] = str(exc)
            _trace(
                "TOOL_END",
                {
                    "id": call_id,
                    "tool": tool.name,
                    "status": "error",
                    "elapsed_s": round(elapsed, 3),
                    "error": str(exc),
                },
            )
            raise

    return RuntimeTool(
        name=tool.name,
        description=tool.description,
        input_schema=tool.input_schema,
        executor=traced_coroutine,
        defaults=tool.defaults,
    )


async def _enable_tool_tracing() -> tuple[Any, Any]:
    bridge = await get_mcp_bridge()
    original_get_tools = bridge.get_tools_for_agent

    def traced_get_tools(allowed_tools=None):
        tools = original_get_tools(allowed_tools)
        return [_wrap_tool_with_trace(tool) for tool in tools]

    bridge.get_tools_for_agent = traced_get_tools
    return bridge, original_get_tools


async def _require_live_prereqs() -> None:
    cfg = get_runtime_config()
    if not cfg.openrouter_api_key or not cfg.openrouter_model:
        pytest.skip("Minimal Striker live test requires OPENROUTER_API_KEY and OPENROUTER_MODEL.")

    try:
        bridge = await get_mcp_bridge()
        striker_tools = {tool.name for tool in bridge.get_tools_for_agent(striker_module.STRIKER_ALLOWED_TOOLS)}
    except Exception as exc:
        pytest.skip(f"Live attackbox MCP bridge is unavailable: {exc}")

    required = {
        "msf_search_modules",
        "msf_get_module_options",
        "msf_run_exploit",
        "msf_run_auxiliary",
        "msf_list_sessions",
    }
    if not required.issubset(striker_tools):
        missing = sorted(required - striker_tools)
        pytest.skip(f"Striker live tools unavailable: missing {missing}")


def _minimal_state(mission_id: str) -> CyberState:
    state = build_initial_state(
        mission_goal=f"Plan one plausible exploitation path for {MINIMAL_TARGET} using only minimal seed evidence",
        target_scope=[MINIMAL_TARGET],
        mission_id=mission_id,
    )
    state["current_agent"] = "striker"
    state["next_agent"] = None
    state["discovered_targets"] = {
        MINIMAL_TARGET: {
            "ip_address": MINIMAL_TARGET,
            "ports": [8000],
            "services": {
                "8000": {
                    "port": 8000,
                    "protocol": "tcp",
                    "service_name": "http",
                    "version": "",
                    "banner": "",
                }
            },
        }
    }
    state["web_findings"] = []
    state["research_cache"] = {}
    state["intelligence_findings"] = []
    state["fuzzing_runs"] = []
    return state


async def _execute_minimal_live_flow(mission_id: str) -> Dict[str, Any]:
    await _require_live_prereqs()
    TRACE_EVENTS.clear()
    bridge, original_get_tools = await _enable_tool_tracing()

    try:
        _step("Loading minimal Striker state")
        state = _minimal_state(mission_id)
        context_preview = striker_module._build_striker_context(state)
        _trace(
            "MINIMAL_STATE_SUMMARY",
            {
                "target": MINIMAL_TARGET,
                "ports": state["discovered_targets"][MINIMAL_TARGET]["ports"],
                "web_findings_count": len(state.get("web_findings", []) or []),
                "research_keys": sorted((state.get("research_cache") or {}).keys()),
                "intelligence_count": len(state.get("intelligence_findings", []) or []),
            },
        )
        print(f"[minimal-trace] STRIKER_CONTEXT:\n{context_preview[:12000]}", flush=True)

        approval_mode = _approval_mode_label()
        _step(f"Running minimal live Striker planning turn in {approval_mode} mode")
        _trace(
            "STRIKER_CALL_START",
            {
                "timeout_seconds": MINIMAL_STRIKER_TIMEOUT_SECONDS,
                "target_count": len(state.get("discovered_targets", {}) or {}),
                "web_findings_count": len(state.get("web_findings", []) or []),
            },
        )
        original_require_manual_approval = striker_module.require_manual_approval
        if LIVE_STRIKER_INTERACTIVE_APPROVAL:
            striker_module.require_manual_approval = original_require_manual_approval
        elif LIVE_STRIKER_EXECUTE:
            striker_module.require_manual_approval = lambda **kwargs: True
        else:
            striker_module.require_manual_approval = lambda **kwargs: False
        _trace(
            "STRIKER_APPROVAL_MODE",
            {
                "mode": approval_mode,
                "live_striker_execute": LIVE_STRIKER_EXECUTE,
                "interactive_approval": LIVE_STRIKER_INTERACTIVE_APPROVAL,
            },
        )
        try:
            result = await asyncio.wait_for(
                striker_module.striker_node(state),
                timeout=MINIMAL_STRIKER_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise RuntimeError(
                "Minimal Striker planning turn timed out before returning. "
                f"Current timeout={MINIMAL_STRIKER_TIMEOUT_SECONDS}s."
            ) from exc
        finally:
            striker_module.require_manual_approval = original_require_manual_approval

        _trace(
            "STRIKER_CALL_END",
            {
                "agent_log_entries": len(result.get("agent_log", []) or []),
                "error_count": len(result.get("errors", []) or []),
                "active_sessions": len(result.get("active_sessions", {}) or {}),
            },
        )
        return {
            "state": state,
            "context_preview": context_preview,
            "result": result,
            "trace_events": list(TRACE_EVENTS),
        }
    finally:
        bridge.get_tools_for_agent = original_get_tools


def _extract_log_entry(result: Dict[str, Any]) -> Dict[str, Any]:
    logs = result.get("agent_log", []) or []
    if not logs:
        return {}
    entry = logs[0]
    return entry.model_dump() if hasattr(entry, "model_dump") else dict(entry)


def _validate_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    result = payload["result"]
    context_preview = payload["context_preview"]
    trace_events = payload["trace_events"]

    assert result["current_agent"] == "striker"
    assert result["iteration_count"] == 1
    assert not result.get("errors"), result.get("errors")
    assert "TARGET INTELLIGENCE:" in context_preview
    assert "CANDIDATE PATHS:" in context_preview
    assert "http" in context_preview.lower()

    log_entry = _extract_log_entry(result)
    findings = log_entry.get("findings") or {}
    assert log_entry, "Minimal run should still produce an agent_log entry"
    assert findings or trace_events, "Minimal run should either record findings or show tool activity"
    assert findings.get("status") in {
        "approval_blocked",
        "no_candidate",
        "validated_no_session",
        "session_opened",
        "execution_error",
    }
    if not result.get("active_sessions"):
        assert findings.get("session_opened") is False

    summary = {
        "mission_id": payload["state"]["mission_id"],
        "target": MINIMAL_TARGET,
        "trace_tools": sorted({str(event.get("tool") or "") for event in trace_events}),
        "findings_status": findings.get("status"),
        "selected_module": findings.get("selected_module") or findings.get("module"),
        "executed_tool": findings.get("executed_tool"),
        "executed_module": findings.get("executed_module"),
        "session_opened": findings.get("session_opened"),
        "approval_mode": _approval_mode_label(),
        "execution_enabled": LIVE_STRIKER_EXECUTE,
        "interactive_approval": LIVE_STRIKER_INTERACTIVE_APPROVAL,
    }
    _trace("MINIMAL_STRIKER_SUMMARY", summary)
    return summary


def test_striker_live_minimal_state():
    mission_id = _mission_id()
    payload = _run(_execute_minimal_live_flow(mission_id))
    summary = _validate_payload(payload)
    print(json.dumps(summary, indent=2, default=str))


def main() -> int:
    mission_id = _mission_id()
    try:
        payload = _run(_execute_minimal_live_flow(mission_id))
        summary = _validate_payload(payload)
    except pytest.skip.Exception as exc:
        print(f"[minimal-skip] {exc}")
        return 0
    except RuntimeError as exc:
        print(f"[minimal-fail] {exc}")
        return 1
    except AssertionError as exc:
        print(f"[minimal-fail] {exc}")
        return 1

    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
