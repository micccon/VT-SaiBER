#!/usr/bin/env python3
"""
Striker Live Test: Kali nmap -> Striker (with full tool-call trace)
====================================================================
Flow:
1. Call Kali MCP nmap_scan against automotive-testbed (or TARGET_HOST)
2. Parse nmap output into discovered_targets CyberState structure
3. Run real striker_node with OpenRouter
4. Print full tool-call trace (tool name, args, elapsed, result preview)

Run inside agents container:
  docker exec -it \
    -e OPENROUTER_API_KEY=... \
    -e LLM_CLIENT=openrouter \
    -e LLM_MODEL=meta-llama/llama-3.1-8b-instruct:free \
    -e STRIKER_REQUIRE_CONFIRMATION=true \
    -e TARGET_HOST=automotive-testbed \
    vt-saiber-agents \
    python3 -u /app/tests/agent_tests/test_striker_nmap_openrouter_trace.py
"""

import asyncio
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.tools import StructuredTool

sys.path.insert(0, "/app")

from src.agents.striker import striker_node
from src.mcp.mcp_tool_bridge import get_mcp_bridge


TRACE_EVENTS: List[Dict[str, Any]] = []


def _parse_json(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return {"raw": raw}
    return {"raw": str(raw)}


def _result_preview(value: Any, max_chars: int = 3500) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, default=str, indent=2)
    return text[:max_chars] + ("...(truncated)" if len(text) > max_chars else "")


def _base_tool_name(tool_name: str) -> str:
    return tool_name.split("_", 1)[1] if "_" in tool_name else tool_name


def _find_tool(bridge, base_name: str) -> Optional[StructuredTool]:
    for tool in bridge.all_tools:
        if _base_tool_name(tool.name) == base_name:
            return tool
    return None


def _trace_print(label: str, payload: Dict[str, Any]) -> None:
    print(f"[TRACE] {label}: {json.dumps(payload, default=str)}")


def _wrap_tool_with_trace(tool: StructuredTool) -> StructuredTool:
    async def traced_coroutine(**kwargs):
        call_id = len(TRACE_EVENTS) + 1
        started = time.perf_counter()
        event = {
            "id": call_id,
            "tool": tool.name,
            "args": kwargs,
            "status": "started",
        }
        TRACE_EVENTS.append(event)
        _trace_print("TOOL_START", {"id": call_id, "tool": tool.name, "args": kwargs})
        try:
            if tool.coroutine is not None:
                result = await tool.coroutine(**kwargs)
            elif tool.func is not None:
                result = tool.func(**kwargs)
            else:
                raise RuntimeError(f"Tool {tool.name} has no callable handler")
            elapsed = time.perf_counter() - started
            event["status"] = "ok"
            event["elapsed_s"] = round(elapsed, 3)
            event["result_preview"] = _result_preview(result, max_chars=1200)
            _trace_print(
                "TOOL_END",
                {
                    "id": call_id,
                    "tool": tool.name,
                    "status": "ok",
                    "elapsed_s": round(elapsed, 3),
                },
            )
            print(f"[TRACE] TOOL_RESULT[{call_id}]:\n{_result_preview(result)}")
            return result
        except Exception as exc:
            elapsed = time.perf_counter() - started
            event["status"] = "error"
            event["elapsed_s"] = round(elapsed, 3)
            event["error"] = str(exc)
            _trace_print(
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

    return StructuredTool(
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        func=tool.func,
        coroutine=traced_coroutine,
    )


def _parse_nmap_services(stdout: str) -> Tuple[List[int], Dict[str, Dict[str, str]], str]:
    ports: List[int] = []
    services: Dict[str, Dict[str, str]] = {}
    os_guess = "unknown"

    in_table = False
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("PORT") and "SERVICE" in line:
            in_table = True
            continue

        if line.startswith("Service Info:"):
            os_match = re.search(r"OS:\s*([^;]+)", line)
            if os_match:
                os_guess = os_match.group(1).strip()
            continue

        if not in_table:
            continue

        if line.startswith("Nmap done:") or line.startswith("MAC Address:"):
            in_table = False
            continue

        # Example: 22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
        match = re.match(r"^(\d+)/tcp\s+(\S+)\s+(\S+)\s*(.*)$", line)
        if not match:
            continue

        port = int(match.group(1))
        state = match.group(2).lower()
        service_name = match.group(3).lower()
        version = match.group(4).strip()
        if state != "open":
            continue

        ports.append(port)
        services[str(port)] = {
            "service_name": service_name,
            "version": version,
            "banner": "",
        }

    return sorted(ports), services, os_guess


def _build_state_from_nmap(target_host: str, nmap_stdout: str) -> Dict[str, Any]:
    ports, services, os_guess = _parse_nmap_services(nmap_stdout)
    if not ports:
        # Fallback for environments where version table is sparse
        # so striker still receives basic SSH context if present in output.
        if "22/tcp" in nmap_stdout and "open" in nmap_stdout:
            ports = [22]
            services["22"] = {
                "service_name": "ssh",
                "version": "",
                "banner": "",
            }

    return {
        "mission_goal": f"Gain initial access to {target_host}",
        "mission_id": "striker-live-nmap-trace",
        "mission_status": "active",
        "current_agent": "striker",
        "next_agent": None,
        "iteration_count": 0,
        "target_scope": [target_host],
        "discovered_targets": {
            target_host: {
                "ip_address": target_host,
                "os_guess": os_guess,
                "ports": ports,
                "services": services,
                "vulns": [],
            }
        },
        "web_findings": [],
        "research_cache": {},
        "osint_findings": [],
        "active_sessions": {},
        "exploited_services": [],
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }


async def main() -> None:
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        print("[FAIL] OPENROUTER_API_KEY is not set.")
        raise SystemExit(1)

    # Enforce expected runtime for this live test.
    os.environ["LLM_CLIENT"] = os.getenv("LLM_CLIENT", "openrouter")
    os.environ["LLM_MODEL"] = os.getenv("LLM_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
    os.environ["STRIKER_REQUIRE_CONFIRMATION"] = os.getenv("STRIKER_REQUIRE_CONFIRMATION", "true")

    target_host = os.getenv("TARGET_HOST", "automotive-testbed").strip() or "automotive-testbed"
    scan_type = os.getenv("NMAP_SCAN_TYPE", "-sS -sV -sC")
    scan_ports = os.getenv("NMAP_PORTS", "")
    nmap_args = os.getenv("NMAP_ADDITIONAL_ARGS", "-Pn -T4")

    print("=" * 76)
    print("Striker Live Test: Kali nmap -> Striker (full tool-call trace)")
    print("=" * 76)
    print(f"TARGET_HOST={target_host}")
    print(f"NMAP_SCAN_TYPE={scan_type}")
    print(f"NMAP_PORTS={scan_ports or '(default)'}")
    print(f"NMAP_ADDITIONAL_ARGS={nmap_args}")
    print(f"LLM_CLIENT={os.getenv('LLM_CLIENT')}")
    print(f"LLM_MODEL={os.getenv('LLM_MODEL')}")
    print(f"STRIKER_REQUIRE_CONFIRMATION={os.getenv('STRIKER_REQUIRE_CONFIRMATION')}")

    bridge = await get_mcp_bridge()
    nmap_tool = _find_tool(bridge, "nmap_scan")
    if nmap_tool is None:
        print("[FAIL] kali_nmap_scan tool not found via MCP bridge.")
        raise SystemExit(1)

    traced_nmap_tool = _wrap_tool_with_trace(nmap_tool)

    print("\n--- Step 1: Run Kali nmap_scan via MCP ---")
    nmap_raw = await traced_nmap_tool.coroutine(
        target=target_host,
        scan_type=scan_type,
        ports=scan_ports,
        additional_args=nmap_args,
    )
    nmap_result = _parse_json(nmap_raw)
    nmap_stdout = nmap_result.get("stdout", "")
    nmap_stderr = nmap_result.get("stderr", "")
    if nmap_stderr:
        print("\n[nmap stderr]")
        print(nmap_stderr[:2000])

    if not nmap_stdout:
        print("[FAIL] nmap_scan returned no stdout; cannot build discovered_targets.")
        print(json.dumps(nmap_result, indent=2, default=str))
        raise SystemExit(1)

    state = _build_state_from_nmap(target_host, nmap_stdout)
    target_data = state["discovered_targets"][target_host]
    print("\n--- Derived discovered_targets ---")
    print(json.dumps(target_data, indent=2))

    print("\n--- Step 2: Run Striker with traced MCP tools ---")
    original_get_tools = bridge.get_tools_for_agent

    def traced_get_tools(allowed_tools=None):
        tools = original_get_tools(allowed_tools)
        return [_wrap_tool_with_trace(t) for t in tools]

    bridge.get_tools_for_agent = traced_get_tools
    try:
        out = await striker_node(state)
    finally:
        bridge.get_tools_for_agent = original_get_tools

    print("\n--- Striker output summary ---")
    print(f"iteration_count: {out.get('iteration_count')}")
    print(f"critical_findings: {out.get('critical_findings', [])}")
    print(f"active_sessions: {list((out.get('active_sessions') or {}).keys())}")
    print(f"exploited_services entries: {len(out.get('exploited_services', []))}")
    if out.get("errors"):
        print("errors:")
        print(json.dumps(out.get("errors"), indent=2, default=str))

    print("\n--- Full tool-call sequence ---")
    for event in TRACE_EVENTS:
        print(
            f"{event.get('id')}. {event.get('tool')} "
            f"status={event.get('status')} elapsed={event.get('elapsed_s', '?')}s"
        )

    if len(TRACE_EVENTS) <= 1:
        # One event means only the initial nmap call ran and striker made no tool calls.
        print("[WARN] No striker MCP tool calls were observed after nmap.")

    print("\n[PASS] Striker nmap->react trace test completed.")


if __name__ == "__main__":
    asyncio.run(main())
