"""
Resident Agent - Post-Exploitation Specialist
=============================================
Maintains access and performs post-exploitation activities on open sessions.
Uses LangGraph's create_react_agent for autonomous enumeration and escalation.

Intelligence sources consumed:
  - active_sessions     (Striker: open MSF sessions keyed by target IP)
  - discovered_targets  (Scout: services and OS context)
  - research_cache      (Librarian: keyed intel — RAG hook-in point)
  - osint_findings      (Librarian: CVE / technique records)
  - mission_goal        (Supervisor: overall objective)

Tool access (docs/visuals/access_control_matrix.txt):
  MSF: list_active_sessions, send_session_command, run_post_module,
       list_exploits, terminate_session
"""

import json
import inspect
import os
from datetime import datetime
from typing import Any, Dict, List

from langchain_core.messages import ToolMessage
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

RESIDENT_ALLOWED_TOOLS = {
    "list_active_sessions",   # MSF: verify sessions are still alive
    "send_session_command",   # MSF: run commands inside a session (enum, privesc)
    "run_post_module",        # MSF: run post-exploitation modules
    "list_exploits",          # MSF: search for privilege escalation modules
    "terminate_session",      # MSF: close a session when done
}

# ToolMessage names to scan for post-exploitation results
POST_TOOL_NAMES = {"msf_send_session_command", "msf_run_post_module"}

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

RESIDENT_SYSTEM_PROMPT = """You are a post-exploitation specialist for authorized penetration testing.

Your job (work through all active sessions provided in context):
1. Call list_active_sessions to confirm which sessions are still alive
2. For each live session, enumerate the system:
   - send_session_command: run "id", "whoami", "uname -a", "hostname", "ip addr"
3. Analyze the results:
   - If running as root/SYSTEM: skip privilege escalation
   - If running as low-privilege user: search for a local privilege escalation module
     using list_exploits (search_term="linux local privilege escalation" or similar)
4. Run relevant post-exploitation modules with run_post_module:
   - post/linux/gather/enum_system  (system enumeration)
   - post/multi/gather/env          (environment variables)
   - post/linux/gather/hashdump     (password hashes, if root)
5. Summarize findings: current user, OS/kernel, privilege escalation result,
   any sensitive data found

Rules:
- Only work on sessions listed in your context — do not target other hosts
- Do not terminate sessions unless explicitly instructed
- If a session appears dead (not in list_active_sessions), note it and move on
- When running post modules, always set SESSION to the session ID from your context
"""


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
    model = os.getenv("LLM_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
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
    return create_react_agent(model=model, tools=tools)

# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _build_resident_context(state: CyberState) -> str:
    """Format CyberState post-exploitation context for the ReAct agent."""
    active_sessions = state.get("active_sessions", {}) or {}
    discovered_targets = state.get("discovered_targets", {}) or {}
    research_cache = state.get("research_cache", {}) or {}
    osint_findings = state.get("osint_findings", []) or []

    # Sessions block
    sessions_lines = []
    for target, info in active_sessions.items():
        sid = info.get("session_id", "?")
        module = info.get("module", "unknown")
        established = info.get("established_at", "?")
        sessions_lines.append(
            f"  session_id={sid}  target={target}  via={module}  opened={established}"
        )
    sessions_block = "\n".join(sessions_lines) if sessions_lines else "  (none)"

    # Target context block
    target_lines = []
    for ip, data in discovered_targets.items():
        os_guess = data.get("os_guess", "unknown")
        services = data.get("services", {})
        svc_names = [
            v.get("service_name", str(v)) if isinstance(v, dict) else str(v)
            for v in list(services.values())[:5]
        ]
        target_lines.append(f"  {ip}  OS: {os_guess}  services: {', '.join(svc_names)}")
    targets_block = "\n".join(target_lines) if target_lines else "  (none)"

    # Research / RAG context
    # RAG hook-in point: when rag_engine.py is ready, replace the lines below with
    #   research_lines = await rag_engine.retrieve(query=mission_goal, top_k=5)
    research_lines = []
    for key, value in list(research_cache.items())[:4]:
        research_lines.append(f"  {key}: {str(value)[:120]}")
    for finding in osint_findings[:3]:
        if isinstance(finding, dict):
            desc = finding.get("description", "")
            cve = finding.get("cve", "")
            if desc:
                prefix = f"[{cve}] " if cve else ""
                research_lines.append(f"  OSINT: {prefix}{desc[:120]}")
    research_block = "\n".join(research_lines) if research_lines else "  (none)"

    return (
        f"MISSION: {state.get('mission_goal') or '(not specified)'}\n\n"
        f"ACTIVE SESSIONS:\n{sessions_block}\n\n"
        f"TARGET CONTEXT:\n{targets_block}\n\n"
        f"RESEARCH & OSINT INTELLIGENCE:\n{research_block}\n\n"
        "Begin post-exploitation. Enumerate each live session, assess privilege level, "
        "run appropriate post modules, and summarize your findings."
    )


# ---------------------------------------------------------------------------
# State update extractor
# ---------------------------------------------------------------------------

def _extract_resident_updates(messages: List, state: CyberState) -> Dict[str, Any]:
    """
    Parse the ReAct agent's message history to build CyberState updates.
    Looks for send_session_command and run_post_module results to extract
    privilege level, OS info, and any critical findings.
    """
    active_sessions = state.get("active_sessions", {}) or {}
    critical_findings: List[str] = []
    findings_summary: Dict[str, Any] = {}

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        if msg.name not in POST_TOOL_NAMES:
            continue

        try:
            data = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
        except (json.JSONDecodeError, TypeError):
            data = {}

        if not isinstance(data, dict):
            continue

        output = data.get("output", "") or data.get("module_output", "") or ""
        status = data.get("status", "")

        # Detect privilege level from command output
        if "uid=0" in output or output.strip().startswith("root"):
            findings_summary["privilege"] = "root"
            critical_findings.append("Post-exploitation: root privileges confirmed")
        elif "uid=" in output and "privilege" not in findings_summary:
            findings_summary["privilege"] = "user"

        # Capture OS info from uname output
        if "linux" in output.lower() and findings_summary.get("os_info") is None:
            findings_summary["os_info"] = output.strip()[:120]

        # Note successful post module runs
        if msg.name == "msf_run_post_module" and status == "success":
            module = data.get("module", "unknown")
            critical_findings.append(f"Post module succeeded: {module}")

    updates: Dict[str, Any] = {
        "iteration_count": state.get("iteration_count", 0) + 1,
        "agent_log": [AgentLogEntry(
            agent="resident",
            action="post_exploitation",
            findings=findings_summary or None,
            reasoning="ReAct agent completed post-exploitation tasks",
        )],
    }

    if critical_findings:
        updates["critical_findings"] = critical_findings

    # Enrich active_sessions with discovered privilege/OS info
    if findings_summary and active_sessions:
        enriched = {}
        for target, info in active_sessions.items():
            enriched[target] = {
                **info,
                **findings_summary,
                "post_exploitation_at": datetime.now().isoformat(),
            }
        updates["active_sessions"] = enriched

    return updates


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------

async def resident_node(state: CyberState) -> Dict[str, Any]:
    """Resident node for LangGraph — autonomous ReAct post-exploitation agent."""

    # Validate prerequisites
    active_sessions = state.get("active_sessions", {})
    if not active_sessions:
        return {
            "errors": [AgentError(
                agent="resident",
                error_type="ValidationError",
                error="No active sessions — run Striker first",
                recoverable=True,
            )],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    # Acquire MCP tools from bridge
    bridge = await get_mcp_bridge()
    tools = bridge.get_tools_for_agent(RESIDENT_ALLOWED_TOOLS)

    if not tools:
        return {
            "errors": [AgentError(
                agent="resident",
                error_type="ToolError",
                error="No MSF tools available — is msf-mcp running?",
                recoverable=False,
            )],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    tool_names = {t.name for t in tools}
    if "msf_send_session_command" not in tool_names:
        return {
            "errors": [AgentError(
                agent="resident",
                error_type="ToolError",
                error="Required tool msf_send_session_command missing from bridge",
                recoverable=False,
            )],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    # Build and run the ReAct agent
    llm = _build_llm()
    agent = _create_react_agent_with_prompt(
        model=llm,
        tools=tools,
        system_prompt=RESIDENT_SYSTEM_PROMPT,
    )

    print(f"[Resident] Starting ReAct agent — {len(active_sessions)} active session(s)")

    user_msg = _build_resident_context(state)
    result = await agent.ainvoke({"messages": [("human", user_msg)]})

    return _extract_resident_updates(result["messages"], state)
