"""
Striker Agent - Exploitation Specialist
======================================
Gains initial access using Metasploit via MCP tools.
Uses LangGraph's create_react_agent for autonomous tool selection and execution.

Key behaviors:
- Dynamic ReAct planning from current CyberState intelligence (no hardcoded exploit path)
- Manual confirmation gate before exploit-execution tool calls
- Configurable LLM backend (Anthropic / OpenRouter / Ollama / OpenAI)

Intelligence sources consumed:
  - discovered_targets  (Scout: services with name + version per port)
  - web_findings        (Fuzzer: discovered paths, status codes)
  - research_cache      (Librarian: keyed intel)
  - osint_findings      (Librarian: structured CVE / exploit records)
  - mission_goal        (Supervisor: overall objective)

Tool access (docs/visuals/access_control_matrix.txt):
  MSF: list_exploits, list_payloads, get_module_options,
       run_exploit, run_auxiliary_module, list_active_sessions
"""

import asyncio
import inspect
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain_core.messages import ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.prebuilt import create_react_agent

from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.state.cyber_state import CyberState
from src.state.models import AgentError, AgentLogEntry

try:
    from langchain_openai import ChatOpenAI
except Exception:  # pragma: no cover - optional dependency path
    ChatOpenAI = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STRIKER_ALLOWED_TOOLS = {
    # Metasploit tools
    "list_exploits",          # search modules by keyword
    "get_module_info",        # concise module metadata and compatible payload hints
    "list_payloads",          # payload discovery by platform/arch
    "get_module_options",     # module option metadata (supports advanced/search)
    "run_exploit",            # execute exploit modules
    "run_auxiliary_module",   # execute auxiliary modules (ssh_login, ftp_login, etc.)
    "list_active_sessions",   # returns {"status", "sessions": {id: info}, "count"}
    # Kali tools
    "hydra_attack",           # credential brute-force workflows
    "john_crack",             # offline password hash cracking
    "sqlmap_scan",            # SQLi verification/exploitation
    "execute_command",        # controlled command execution for support tooling
}

MAX_EXPLOIT_ATTEMPTS = 3
MAX_INFO_GATHER_CALLS = int(os.getenv("STRIKER_MAX_INFO_CALLS", "12"))
MAX_EXPLOIT_SEARCH_CALLS = int(os.getenv("STRIKER_MAX_EXPLOIT_SEARCH_CALLS", "4"))

# DoS / destructive module patterns — agent is instructed never to use these
FORBIDDEN_MODULE_PATTERNS = [
    "/dos/", "auxiliary/dos", "denial_of_service",
    "synflood", "udpflood", "land", "jolt",
]

# Full tool names as registered on the bridge (server prefix + MCP tool name)
EXPLOIT_TOOL_NAMES = {"msf_run_exploit", "msf_run_auxiliary_module"}
EXPLOIT_BASE_TOOL_NAMES = {"run_exploit", "run_auxiliary_module"}
INFO_TOOL_NAMES = {
    "msf_list_exploits",
    "msf_get_module_info",
    "msf_get_module_options",
    "msf_list_payloads",
}

# Manual approval gate (default: ON)
STRIKER_REQUIRE_CONFIRMATION = os.getenv("STRIKER_REQUIRE_CONFIRMATION", "true").lower() == "true"


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

STRIKER_SYSTEM_PROMPT = f"""You are an exploitation specialist for authorized penetration testing.

Operate as a dynamic ReAct agent:
1. Analyze current target intelligence from context (services, versions, OS hints, web findings, OSINT)
2. Select reconnaissance/exploitation actions based on evidence, not fixed playbooks
3. Use these tools to reason and adapt:
   - Metasploit:
     - list_exploits(search_term)
     - get_module_info(module_type, module_name)
     - list_payloads(platform, arch)
     - get_module_options(module_type, module_name, search, advanced)
     - run_auxiliary_module(...)
     - run_exploit(...)
     - list_active_sessions()
   - Kali:
     - hydra_attack(...)
     - john_crack(...)
     - sqlmap_scan(...)
     - execute_command(...)
4. Before executing a module, inspect options with get_module_options and set required fields explicitly
5. After each exploit attempt, verify outcome with list_active_sessions
6. Try alternate techniques if no session is opened (max {MAX_EXPLOIT_ATTEMPTS} exploit attempts)
7. Finish with a concise summary of attempted modules, rationale, and session outcome

Tool intent quick reference:
- list_exploits: search exploit modules only (not auxiliary modules like scanner/ssh/ssh_login)
- get_module_info: concise module details and payload compatibility hints; call before options
- get_module_options: inspect one selected module's required fields before execution
- run_auxiliary_module: scanners/credential checks and auxiliary workflows
- run_exploit: exploit module execution for RCE/initial shell
- list_active_sessions: verify outcome after every execution attempt
- hydra_attack/john_crack/sqlmap_scan/execute_command: support actions only when directly justified

Selection policy (strict):
1) Build a shortlist of up to 3 candidate paths from observed services/versions.
2) For each candidate, do at most one targeted list_exploits(search_term), then get_module_info, then get_module_options.
3) Do not repeat identical tool calls with the same arguments.
4) Never call list_exploits with an empty search_term.
5) After enough evidence, execute the best-ranked single candidate instead of enumerating broadly.
6) If exploit searches repeatedly return empty, pivot to auxiliary or supporting credential workflows.

Rules:
- NEVER run DoS, flood, or destructive modules (patterns: {', '.join(FORBIDDEN_MODULE_PATTERNS)})
- Do not hardcode exploit decisions; derive choices from evidence in context and tool outputs
- For ssh_login-style auxiliary credential checks, include STOP_ON_SUCCESS=true and VERBOSE=true
- Always set target options (e.g., RHOSTS/RPORT) from current target context
- Manual approval is required by the runtime before exploit execution tools are actually run
- Use execute_command only for controlled supporting actions relevant to exploitation
"""


# ---------------------------------------------------------------------------
# LLM selection
# ---------------------------------------------------------------------------


def _build_llm():
    provider = os.getenv("LLM_CLIENT", "openrouter").strip().lower()
    if provider != "openrouter":
        raise RuntimeError(
            f"Unsupported LLM_CLIENT='{provider}'. "
            "Current VT-SaiBER config supports openrouter only."
        )
    if ChatOpenAI is None:
        raise RuntimeError("langchain-openai is not installed")
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is required when LLM_CLIENT=openrouter")
    model_override = os.getenv("LLM_MODEL")
    model = model_override or "meta-llama/llama-3.1-8b-instruct:free"
    return ChatOpenAI(
        model=model,
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        temperature=0,
    )


def _create_react_agent_with_prompt(model, tools, system_prompt: str):
    """
    Handle LangGraph API drift:
    - newer versions: create_react_agent(..., prompt=...)
    - older versions: create_react_agent(..., state_modifier=...)
    """
    try:
        sig = inspect.signature(create_react_agent)
        params = sig.parameters
    except Exception:
        params = {}

    if "prompt" in params:
        return create_react_agent(model=model, tools=tools, prompt=system_prompt)
    if "state_modifier" in params:
        return create_react_agent(model=model, tools=tools, state_modifier=system_prompt)
    # Last resort: rely on defaults and let caller-supplied user context drive behavior.
    return create_react_agent(model=model, tools=tools)


# ---------------------------------------------------------------------------
# Service parsing
# ---------------------------------------------------------------------------


def _parse_services(target_data: Dict) -> List[Dict]:
    """Extract structured service list from a discovered_targets entry."""
    raw = target_data.get("services", {})
    result = []
    for port_key, svc in raw.items():
        port = int(port_key) if not isinstance(port_key, int) else port_key
        if isinstance(svc, dict):
            name = svc.get("service_name", "").lower()
            version = svc.get("version", "") or ""
            banner = svc.get("banner", "") or ""
        else:
            parts = str(svc).split()
            name = parts[0].lower() if parts else "unknown"
            version = " ".join(parts[1:]) if len(parts) > 1 else ""
            banner = ""
        result.append({"port": port, "name": name, "version": version, "banner": banner})
    return sorted(result, key=lambda x: x["port"])


# ---------------------------------------------------------------------------
# Research hints
# ---------------------------------------------------------------------------


def _collect_research_hints(state: CyberState, services: List[Dict]) -> List[str]:
    """Pull relevant intel from research_cache and osint_findings in state."""
    hints: List[str] = []
    research_cache = state.get("research_cache", {}) or {}
    osint_findings = state.get("osint_findings", []) or []

    keywords: set = set()
    for svc in services:
        keywords.add(svc["name"].lower())
        if svc["version"]:
            keywords.add(svc["version"].lower())
            keywords.add(svc["version"].split()[0].lower())

    for key, value in research_cache.items():
        if any(kw in key.lower() for kw in keywords):
            hints.append(f"Research ({key}): {value}")

    for finding in osint_findings:
        if isinstance(finding, dict):
            desc = finding.get("description", "")
            cve = finding.get("cve", "")
            msf_module = finding.get("data", {}).get("msf_module", "")
            if any(kw in desc.lower() for kw in keywords):
                hint = "OSINT"
                if cve:
                    hint += f" [{cve}]"
                hint += f": {desc}"
                if msf_module:
                    hint += f" (MSF: {msf_module})"
                hints.append(hint)

    return hints


# ---------------------------------------------------------------------------
# Manual confirmation wrappers
# ---------------------------------------------------------------------------


def _tool_base_name(tool_name: str) -> str:
    return tool_name.split("_", 1)[1] if "_" in tool_name else tool_name


def _is_exploit_tool(tool_name: str) -> bool:
    return _tool_base_name(tool_name) in EXPLOIT_BASE_TOOL_NAMES


def _format_exploit_request(tool_name: str, kwargs: Dict[str, Any]) -> str:
    module_name = kwargs.get("module_name", "unknown")
    options = kwargs.get("options", {}) if isinstance(kwargs.get("options"), dict) else {}
    target = options.get("RHOSTS") or options.get("RHOST") or options.get("TARGET") or "unknown"
    port = options.get("RPORT", "")
    target_display = f"{target}:{port}" if port else str(target)
    return f"tool={tool_name}, module={module_name}, target={target_display}"


def _manual_approval_prompt(tool_name: str, kwargs: Dict[str, Any]) -> bool:
    if not STRIKER_REQUIRE_CONFIRMATION:
        return True

    # Safe default: deny when not interactive
    if not sys.stdin or not sys.stdin.isatty():
        print(
            "[Striker] Exploit execution blocked: manual approval required but stdin is non-interactive. "
            "Run interactively or set STRIKER_REQUIRE_CONFIRMATION=false if this is a controlled test run."
        )
        return False

    print("\n[Striker] Manual approval required before exploit execution")
    print(f"[Striker] Proposed action: {_format_exploit_request(tool_name, kwargs)}")
    decision = input("Approve exploit execution? [y/N]: ").strip().lower()
    return decision in {"y", "yes"}


def _blocked_execution_response(tool_name: str, kwargs: Dict[str, Any]) -> str:
    return json.dumps(
        {
            "status": "aborted",
            "message": "Exploit execution blocked pending manual confirmation",
            "tool": tool_name,
            "requested": kwargs,
        },
        default=str,
    )


def _invoke_tool(tool: StructuredTool, kwargs: Dict[str, Any]):
    if tool.coroutine is not None:
        return tool.coroutine(**kwargs)
    if tool.func is not None:
        return asyncio.to_thread(tool.func, **kwargs)
    async def _err():
        return json.dumps({"status": "error", "message": f"Tool {tool.name} has no callable handler"})
    return _err()


def _wrap_tools(tools: List[StructuredTool], require_module_info: bool) -> List[StructuredTool]:
    """
    Add selection-policy and manual-confirmation guardrails in one wrapper layer.
    """
    wrapped: List[StructuredTool] = []
    cache: Dict[str, str] = {}
    state = {"info_calls": 0, "exploit_search_calls": 0, "exploit_empty_search_streak": 0}
    module_info_seen: set[str] = set()
    module_payload_compat: Dict[str, set[str]] = {}

    def _cache_key(tool_name: str, kwargs: Dict[str, Any]) -> str:
        return f"{tool_name}:{json.dumps(kwargs, sort_keys=True, default=str)}"

    def _module_key(module_type: Any, module_name: Any) -> str:
        mtype = str(module_type or "").strip().lower()
        mname = str(module_name or "").strip().lower()
        return f"{mtype}:{mname}" if mtype and mname else ""

    def _parse_tool_result(raw: Any) -> Dict[str, Any]:
        payload: Any = raw
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                return {}
        if not isinstance(payload, dict):
            return {}
        nested = payload.get("result")
        if isinstance(nested, dict):
            return nested
        return payload

    for tool in tools:
        original_tool = tool

        async def guarded_coroutine(_tool=original_tool, **kwargs):
            call_kwargs = dict(kwargs or {})

            # Manual confirmation applies only to exploit-execution tools.
            if _is_exploit_tool(_tool.name):
                if _tool.name == "msf_run_exploit":
                    module_key = _module_key("exploit", call_kwargs.get("module_name"))
                    if require_module_info and module_key and module_key not in module_info_seen:
                        return json.dumps({
                            "status": "requires_module_info",
                            "tool": _tool.name,
                            "module_key": module_key,
                            "message": "Call msf_get_module_info for this exploit module before msf_run_exploit.",
                        })

                    payload_name = str(call_kwargs.get("payload_name") or "").strip()
                    compat_payloads = module_payload_compat.get(module_key)
                    if payload_name and compat_payloads and payload_name not in compat_payloads:
                        suggestions = sorted(compat_payloads)[:8]
                        return json.dumps({
                            "status": "payload_incompatible",
                            "tool": _tool.name,
                            "module_key": module_key,
                            "payload_name": payload_name,
                            "message": f"Payload '{payload_name}' is not listed as compatible for this module.",
                            "compatible_payloads_sample": suggestions,
                        })

                if not _manual_approval_prompt(_tool.name, call_kwargs):
                    return _blocked_execution_response(_tool.name, call_kwargs)
                return await _invoke_tool(_tool, call_kwargs)

            # Selection policy for exploit-discovery/info calls.
            if _tool.name == "msf_list_exploits":
                raw_term = call_kwargs.get("search_term", "")
                search_term = str(raw_term or "").strip()
                call_kwargs["search_term"] = search_term
                if not search_term:
                    return json.dumps({
                        "status": "skipped",
                        "tool": _tool.name,
                        "message": "Empty search_term is not allowed. Use a targeted keyword (service/version/CVE).",
                    })
                state["exploit_search_calls"] += 1
                if state["exploit_search_calls"] > MAX_EXPLOIT_SEARCH_CALLS:
                    return json.dumps({
                        "status": "exploit_search_budget_exceeded",
                        "tool": _tool.name,
                        "message": (
                            f"Exploit search call budget exceeded ({MAX_EXPLOIT_SEARCH_CALLS}). "
                            "Choose from gathered candidates or pivot to auxiliary/supporting tools."
                        ),
                    })

            if require_module_info and _tool.name == "msf_get_module_options":
                key = _module_key(call_kwargs.get("module_type"), call_kwargs.get("module_name"))
                if key and key not in module_info_seen:
                    return json.dumps({
                        "status": "requires_module_info",
                        "tool": _tool.name,
                        "module_key": key,
                        "message": "Call msf_get_module_info for this module before msf_get_module_options.",
                    })

            if _tool.name in INFO_TOOL_NAMES:
                state["info_calls"] += 1
                if state["info_calls"] > MAX_INFO_GATHER_CALLS:
                    return json.dumps({
                        "status": "selection_budget_exceeded",
                        "tool": _tool.name,
                        "message": (
                            f"Information-gathering budget exceeded ({MAX_INFO_GATHER_CALLS}). "
                            "Execute the best candidate now."
                        ),
                    })

                key = _cache_key(_tool.name, call_kwargs)
                if key in cache:
                    return cache[key]

                info_result = await _invoke_tool(_tool, call_kwargs)
                if _tool.name == "msf_list_exploits":
                    parsed = _parse_tool_result(info_result)
                    results = parsed.get("result", parsed)
                    if isinstance(results, list) and len(results) == 0:
                        state["exploit_empty_search_streak"] += 1
                    else:
                        state["exploit_empty_search_streak"] = 0
                    if state["exploit_empty_search_streak"] >= 2:
                        return json.dumps({
                            "status": "empty_exploit_search_streak",
                            "tool": _tool.name,
                            "message": (
                                "Multiple targeted exploit searches returned no matches. "
                                "Pivot to auxiliary modules or supporting credential workflows."
                            ),
                        })
                if _tool.name == "msf_get_module_info":
                    module_key = _module_key(call_kwargs.get("module_type"), call_kwargs.get("module_name"))
                    parsed = _parse_tool_result(info_result)
                    if module_key and parsed.get("status") == "success":
                        module_info_seen.add(module_key)
                        payloads_raw = parsed.get("compatible_payloads", [])
                        if isinstance(payloads_raw, list):
                            module_payload_compat[module_key] = {
                                str(v) for v in payloads_raw if isinstance(v, str) and v.strip()
                            }
                if isinstance(info_result, str):
                    cache[key] = info_result
                return info_result

            return await _invoke_tool(_tool, call_kwargs)

        def guarded_func(_tool=original_tool, **kwargs):
            # Sync path is rarely used in this codepath; keep a safe fallback.
            if _is_exploit_tool(_tool.name) and not _manual_approval_prompt(_tool.name, kwargs):
                return _blocked_execution_response(_tool.name, kwargs)
            if _tool.func is None:
                return json.dumps({"status": "error", "message": f"Tool {_tool.name} has no sync handler"})
            return _tool.func(**kwargs)

        wrapped.append(
            StructuredTool(
                name=original_tool.name,
                description=original_tool.description,
                args_schema=original_tool.args_schema,
                func=guarded_func,
                coroutine=guarded_coroutine,
            )
        )

    return wrapped


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------


def _build_striker_context(state: CyberState) -> str:
    """Format all CyberState intelligence into the user message for the ReAct agent."""
    discovered_targets = state.get("discovered_targets", {}) or {}

    lhost = os.getenv("MSF_LHOST", "msf-mcp")
    lport = os.getenv("MSF_LPORT", "4444")

    targets_block_lines: List[str] = []

    for target_ip, target_data in discovered_targets.items():
        os_guess = target_data.get("os_guess", "") or "unknown"
        services = _parse_services(target_data)
        hints = _collect_research_hints(state, services)

        targets_block_lines.append(f"- TARGET {target_ip}")
        targets_block_lines.append(f"  OS hint: {os_guess}")
        if services:
            targets_block_lines.append("  Services:")
            for svc in services:
                ver = f" ({svc['version']})" if svc["version"] else ""
                targets_block_lines.append(f"    - {svc['port']}/tcp {svc['name']}{ver}")
        else:
            targets_block_lines.append("  Services: (none)")

        if hints:
            targets_block_lines.append("  Relevant research/osint:")
            for hint in hints[:4]:
                targets_block_lines.append(f"    - {hint}")

    targets_block = "\n".join(targets_block_lines) if targets_block_lines else "(no targets)"

    web_findings = state.get("web_findings", []) or []
    web_lines = []
    for wf in web_findings[:10]:
        if isinstance(wf, dict):
            path = wf.get("path", wf.get("url", ""))
            code = wf.get("status_code", "?")
            if wf.get("is_interesting") or code in (200, 201, 204, 301, 302):
                web_lines.append(f"  {code} {path}")
    web_block = "\n".join(web_lines) if web_lines else "  (none)"

    prior_attempts = state.get("exploited_services", []) or []
    attempts_block = []
    for item in prior_attempts[-8:]:
        if isinstance(item, dict):
            attempts_block.append(
                "  - target={target} module={module} status={status} session={session}".format(
                    target=item.get("target", "?"),
                    module=item.get("module", "unknown"),
                    status=item.get("status", "unknown"),
                    session=item.get("session_id", "none"),
                )
            )
    prior_block = "\n".join(attempts_block) if attempts_block else "  (none)"

    candidate_lines: List[str] = []
    for target_ip, target_data in discovered_targets.items():
        services = _parse_services(target_data)
        service_names = {svc["name"] for svc in services}
        versions = " ".join((svc.get("version", "") or "").lower() for svc in services)

        if "ssh" in service_names:
            candidate_lines.append(
                f"  - {target_ip}: SSH credential-access workflow via auxiliary or supporting tools"
            )
        if any(name.startswith("http") for name in service_names):
            if "werkzeug" in versions:
                candidate_lines.append(
                    f"  - {target_ip}: evaluate Werkzeug debug exploit path with compatible payload selection"
                )
            else:
                candidate_lines.append(
                    f"  - {target_ip}: web attack-surface workflow (module or supporting tool based)"
                )
    candidate_block = "\n".join(candidate_lines[:6]) if candidate_lines else "  (none)"

    tool_intent_block = (
        "  - list_exploits: exploit-module search only\n"
        "  - get_module_info: module summary + compatible payload hints\n"
        "  - run_auxiliary_module: scanner/credential modules (e.g., ssh_login)\n"
        "  - hydra_attack: supporting credential brute-force workflow when justified\n"
        "  - run_exploit: exploit modules for shell/code execution\n"
        "  - get_module_options: required fields before execution\n"
        "  - list_active_sessions: verify success after each attempt\n"
    )

    return (
        f"MISSION: {state.get('mission_goal') or '(not specified)'}\n"
        f"LHOST: {lhost}\n"
        f"LPORT: {lport}\n"
        f"Manual exploit approval enabled: {STRIKER_REQUIRE_CONFIRMATION}\n\n"
        f"TARGET INTELLIGENCE:\n{targets_block}\n\n"
        f"INTERESTING WEB FINDINGS:\n{web_block}\n\n"
        f"CANDIDATE WORKFLOWS:\n{candidate_block}\n\n"
        f"TOOL INTENT REFERENCE:\n{tool_intent_block}\n"
        f"PRIOR EXPLOIT ATTEMPTS IN THIS MISSION:\n{prior_block}\n\n"
        "Proceed dynamically:\n"
        "- choose up to 3 strongest candidates (ranked)\n"
        "- use targeted module lookups only (no broad empty searches)\n"
        "- avoid duplicate tool calls with same args\n"
        "- execute the best candidate once evidence is sufficient\n"
        "- verify sessions and adapt\n"
    )


# ---------------------------------------------------------------------------
# State update extractor
# ---------------------------------------------------------------------------


def _extract_striker_updates(messages: List, state: CyberState) -> Dict[str, Any]:
    """
    Parse the ReAct agent's message history to build CyberState updates.
    Looks for ToolMessage results from run_exploit / run_auxiliary_module calls.
    """
    discovered_targets = state.get("discovered_targets", {}) or {}
    default_target = list(discovered_targets.keys())[0] if discovered_targets else "unknown"

    session_id: Optional[int] = None
    last_exploit_record: Dict[str, Any] = {}

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        if msg.name not in EXPLOIT_TOOL_NAMES:
            continue

        try:
            data = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
        except (json.JSONDecodeError, TypeError):
            data = {}

        if not isinstance(data, dict):
            continue

        sid = data.get("session_id") or data.get("session_id_detected")
        options = data.get("options", {}) if isinstance(data.get("options"), dict) else {}
        target = options.get("RHOSTS") or options.get("RHOST") or default_target

        last_exploit_record = {
            "target": target,
            "module": data.get("module", "unknown"),
            "status": data.get("status", "unknown"),
            "session_id": sid,
            "timestamp": datetime.now().isoformat(),
        }
        if sid:
            session_id = sid

    updates: Dict[str, Any] = {
        "iteration_count": state.get("iteration_count", 0) + 1,
        "agent_log": [AgentLogEntry(
            agent="striker",
            action="run_exploit",
            target=last_exploit_record.get("target", default_target),
            findings=last_exploit_record or None,
            reasoning="ReAct striker run complete (manual approval gate enforced for exploit calls)",
        )],
    }

    if last_exploit_record:
        updates["exploited_services"] = [
            *state.get("exploited_services", []),
            last_exploit_record,
        ]

    if session_id is not None:
        lhost = os.getenv("MSF_LHOST", "msf-mcp")
        lport = os.getenv("MSF_LPORT", "4444")
        target = last_exploit_record.get("target", default_target)
        updates["active_sessions"] = {
            **state.get("active_sessions", {}),
            target: {
                "session_id": session_id,
                "module": last_exploit_record.get("module", "unknown"),
                "lhost": lhost,
                "lport": lport,
                "established_at": datetime.now().isoformat(),
            },
        }
        updates["critical_findings"] = [
            f"Session {session_id} opened on {target} via {last_exploit_record.get('module', 'unknown')}"
        ]
        print(f"[Striker] Session {session_id} captured")
    else:
        print("[Striker] No session obtained from ReAct agent run")

    return updates


def _error_update(
    state: CyberState,
    error_type: str,
    message: str,
    recoverable: bool,
) -> Dict[str, Any]:
    return {
        "errors": [AgentError(
            agent="striker",
            error_type=error_type,
            error=message,
            recoverable=recoverable,
        )],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


async def striker_node(state: CyberState) -> Dict[str, Any]:
    """Striker node for LangGraph — autonomous ReAct exploitation agent."""

    discovered_targets = state.get("discovered_targets", {})
    if not discovered_targets:
        return _error_update(
            state,
            error_type="ValidationError",
            message="No discovered targets — run Scout first",
            recoverable=True,
        )

    bridge = await get_mcp_bridge()
    tools = bridge.get_tools_for_agent(STRIKER_ALLOWED_TOOLS)

    if not tools:
        return _error_update(
            state,
            error_type="ToolError",
            message="No MSF tools available — is msf-mcp running?",
            recoverable=False,
        )

    # Safety: ensure exploit tools exist
    tool_names = {t.name for t in tools}
    missing = {"msf_run_exploit", "msf_run_auxiliary_module"} - tool_names
    if missing:
        return _error_update(
            state,
            error_type="ToolError",
            message=f"Required MSF tools missing from bridge: {missing}",
            recoverable=False,
        )

    require_module_info = "msf_get_module_info" in tool_names
    gated_tools = _wrap_tools(tools, require_module_info=require_module_info)

    try:
        llm = _build_llm()
    except Exception as e:
        return _error_update(
            state,
            error_type="LLMConfigError",
            message=str(e),
            recoverable=False,
        )

    agent = _create_react_agent_with_prompt(
        model=llm,
        tools=gated_tools,
        system_prompt=STRIKER_SYSTEM_PROMPT,
    )

    print(f"[Striker] Starting ReAct agent — targets: {list(discovered_targets.keys())}")

    user_msg = _build_striker_context(state)
    result = await agent.ainvoke({"messages": [("human", user_msg)]})

    return _extract_striker_updates(result["messages"], state)
