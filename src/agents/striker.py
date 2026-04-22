"""
Striker Agent - Metasploit-focused exploitation worker.
"""

from __future__ import annotations

import asyncio
import ipaddress
import inspect
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain_core.messages import ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.prebuilt import create_react_agent

from src.agents.base import BaseAgent
from src.database.persistence import persist_state_update
from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.state.cyber_state import CyberState
from src.state.models import AgentError, AgentLogEntry
from src.utils.approval import require_manual_approval
from src.utils.parsers import metasploit_module_key, normalize_tool_result

try:
    from langchain_openai import ChatOpenAI
except Exception:  # pragma: no cover - optional dependency path
    ChatOpenAI = None


STRIKER_ALLOWED_TOOLS = {
    "list_exploits",
    "get_module_info",
    "get_module_options",
    "run_exploit",
    "run_auxiliary_module",
    "list_active_sessions",
}

STRIKER_REQUIRE_CONFIRMATION = os.getenv("STRIKER_REQUIRE_CONFIRMATION", "true").lower() == "true"
MAX_EXPLOIT_ATTEMPTS = int(os.getenv("STRIKER_MAX_EXPLOIT_ATTEMPTS", "3"))
MAX_SEARCH_CALLS = int(os.getenv("STRIKER_MAX_SEARCH_CALLS", "6"))
EXECUTION_TOOL_NAMES = {"msf_run_exploit", "msf_run_auxiliary_module"}
SEARCH_TOOL_NAMES = {"msf_list_exploits"}

CREDENTIAL_MODULES = {
    "scanner/ssh/ssh_login",
    "scanner/ftp/ftp_login",
    "scanner/smb/smb_login",
    "scanner/mysql/mysql_login",
    "scanner/postgres/postgres_login",
    "scanner/vnc/vnc_login",
    "scanner/telnet/telnet_login",
}
CREDENTIAL_OPTIONS = {"USERNAME", "USER_FILE", "USERPASS_FILE", "PASSWORD", "PASS_FILE"}
METASPLOIT_DEFAULT_SERVICES = {
    "http",
    "https",
    "ssh",
    "ftp",
    "smb",
    "telnet",
    "mysql",
    "postgresql",
    "mssql",
    "redis",
    "vnc",
    "rdp",
    "java-rmi",
    "rpcbind",
}


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

    return ChatOpenAI(
        model=os.getenv("LLM_MODEL"),
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
        params = inspect.signature(create_react_agent).parameters
    except Exception:
        params = {}

    if "prompt" in params:
        return create_react_agent(model=model, tools=tools, prompt=system_prompt)
    if "state_modifier" in params:
        return create_react_agent(model=model, tools=tools, state_modifier=system_prompt)
    return create_react_agent(model=model, tools=tools)


def _parse_services(target_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    services = target_data.get("services", {}) or {}
    parsed: List[Dict[str, Any]] = []

    for port_key, service in services.items():
        port = int(port_key) if not isinstance(port_key, int) else port_key
        if isinstance(service, dict):
            parsed.append(
                {
                    "port": port,
                    "name": str(service.get("service_name", "")).lower(),
                    "version": str(service.get("version", "") or ""),
                    "banner": str(service.get("banner", "") or ""),
                }
            )
            continue

        parts = str(service).split()
        parsed.append(
            {
                "port": port,
                "name": parts[0].lower() if parts else "unknown",
                "version": " ".join(parts[1:]) if len(parts) > 1 else "",
                "banner": "",
            }
        )

    return sorted(parsed, key=lambda item: item["port"])


async def _invoke_tool(tool: StructuredTool, kwargs: Dict[str, Any]) -> Any:
    if tool.coroutine is not None:
        return await tool.coroutine(**kwargs)
    if tool.func is not None:
        return await asyncio.to_thread(tool.func, **kwargs)
    return json.dumps({"status": "error", "message": f"Tool {tool.name} has no callable handler"})


def _extract_target_from_execution_args(kwargs: Dict[str, Any]) -> str:
    options = kwargs.get("options", {}) if isinstance(kwargs.get("options"), dict) else {}
    target = options.get("RHOSTS") or options.get("RHOST") or options.get("TARGET")
    return str(target or "unknown")


def _execution_signature(tool_name: str, kwargs: Dict[str, Any]) -> tuple[str, str, str, str]:
    module_name = str(kwargs.get("module_name", "") or "").strip().lower()
    target = _extract_target_from_execution_args(kwargs).strip().lower()
    options = kwargs.get("options", {}) if isinstance(kwargs.get("options"), dict) else {}
    rport = str(options.get("RPORT", "") or "").strip()
    path_hint = str(
        options.get("TARGETURI")
        or options.get("TARGETPATH")
        or options.get("URI")
        or options.get("PATH")
        or ""
    ).strip()
    return (tool_name, module_name, target, f"{rport}:{path_hint}")


def _execution_retry_key(tool_name: str, kwargs: Dict[str, Any]) -> tuple[str, str, str]:
    module_name = str(kwargs.get("module_name", "") or "").strip().lower()
    target = _extract_target_from_execution_args(kwargs).strip().lower()
    return (tool_name, module_name, target)


def _normalize_option_map(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if not isinstance(raw, str):
        return {}

    options: Dict[str, Any] = {}
    for item in raw.split(","):
        key, sep, value = item.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if key:
            options[key] = value
    return options


def _is_invalid_callback_host(value: str) -> bool:
    host = str(value or "").strip().lower()
    if not host or host == "localhost":
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    return ip.is_loopback or ip.is_unspecified


class StrikerAgent(BaseAgent):
    """Thin Metasploit-focused ReAct worker."""

    ALLOWED_TOOLS = STRIKER_ALLOWED_TOOLS

    def __init__(self):
        super().__init__("striker", "Metasploit Agent")
        self.require_confirmation = STRIKER_REQUIRE_CONFIRMATION
        self.max_attempts = MAX_EXPLOIT_ATTEMPTS

    @property
    def system_prompt(self) -> str:
        return f"""You are the VT-SaiBER Metasploit exploitation specialist.

Use only Metasploit MCP tools:
- list_exploits(search_term)
- get_module_info(module_type, module_name)
- get_module_options(module_type, module_name, search, advanced)
- run_exploit(module_name, options, ...)
- run_auxiliary_module(module_name, options, ...)
- list_active_sessions()

Core Rules:
1. Work only from the provided mission context and discovered evidence.
2. Stay Metasploit-only. Do not invent Kali, shell, CAN, or fuzzing actions.
3. Use the ranked candidate paths as guidance, not as a rigid playbook.
4. Search with narrow evidence-based terms derived from the target technology, service, protocol, version, platform, or CVE.
5. Treat exploit search as a precision step, not a brainstorming step.
6. Match the Metasploit module family to the task: exploit modules for exploitation paths, auxiliary modules for scanning, login checks, credential validation, and service interrogation.
7. get_module_info is encouraged when choosing between candidate modules, payloads, and execution approaches.
8. Reverse payloads require a reachable non-loopback LHOST. Never use 127.0.0.1, localhost, or 0.0.0.0.
9. After each execution attempt, check list_active_sessions to verify outcome.
10. Maximum execution attempts per run: {self.max_attempts}.

Path Selection Rules:
- Favor the strongest evidence-backed path over the path with the most tunable options.
- One clean no-session exploit failure should usually lower confidence in that path.
- After a no-session failure, pivot to a meaningfully different path unless genuinely new evidence justifies retrying.
- Do not keep refining a weak exploit path with small guessed changes when the underlying target fit is uncertain.

Option Selection Rules:
- Inspect module options before execution and set required options explicitly from known evidence.
- Prefer the minimum viable option set: fill required options first and avoid setting optional options unless they are clearly justified by evidence or necessary for execution.
- Do not invent strong option values.
- Only set path-like, host/domain-like, protocol/TLS-related, authentication-related, or callback-related options when they are supported by mission context, observed findings, or module/tool output.
- If an option such as TARGETURI, PATH, URI, DOMAIN, VHOST, SSL, SSLVersion, USERNAME, PASSWORD, LHOST, or callback settings is uncertain, omit it or gather more evidence instead of guessing.

Failure Handling Rules:
- If an execution attempt fails and no session is created, reassess the path before trying again.
- Prefer changing the path, module family, or evidence basis over making lightly edited retries.
- Do not retry the same exploit path with lightly edited guessed options after a no-session failure.

Finish with a concise summary of what was attempted, why each path was chosen, and whether a session was opened.
"""

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        validation_error = self._validate_state(state)
        if validation_error is not None:
            return validation_error

        bridge = await get_mcp_bridge()
        tools = bridge.get_tools_for_agent(self.ALLOWED_TOOLS)
        if not tools:
            return self._error_update(
                state,
                error_type="ToolError",
                message="No Metasploit tools available from MCP bridge.",
                recoverable=False,
            )

        wrapped_tools = self._wrap_tools(tools)

        try:
            llm = _build_llm()
        except Exception as exc:
            return self._error_update(
                state,
                error_type="LLMConfigError",
                message=str(exc),
                recoverable=False,
            )

        context = self._build_context(state)
        agent = _create_react_agent_with_prompt(
            model=llm,
            tools=wrapped_tools,
            system_prompt=self.system_prompt,
        )
        result = await agent.ainvoke({"messages": [("human", context)]})
        return self._extract_updates(result.get("messages", []), state)

    def _validate_state(self, state: CyberState) -> Optional[Dict[str, Any]]:
        discovered_targets = state.get("discovered_targets", {}) or {}
        if discovered_targets:
            return None

        return self._error_update(
            state,
            error_type="ValidationError",
            message="No discovered targets available for Metasploit exploitation.",
            recoverable=True,
        )

    def _validate_execution_request(self, tool_name: str, kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Validate reverse payload LHOST for exploits
        if tool_name == "msf_run_exploit":
            payload_name = str(kwargs.get("payload_name", "") or "").strip().lower()
            if "reverse" in payload_name:
                payload_options = _normalize_option_map(kwargs.get("payload_options"))
                lhost = str(payload_options.get("LHOST", "") or "").strip()
                if _is_invalid_callback_host(lhost):
                    return {
                        "status": "blocked",
                        "message": "Reverse payload requires a reachable non-loopback LHOST.",
                        "payload_name": kwargs.get("payload_name", ""),
                        "payload_options": payload_options,
                    }

        # Validate credentials for login scanner modules
        if tool_name == "msf_run_auxiliary_module":
            module_name = str(kwargs.get("module_name", "") or "").strip().lower()
            if any(cred_module in module_name for cred_module in CREDENTIAL_MODULES):
                options = kwargs.get("options", {}) if isinstance(kwargs.get("options"), dict) else {}
                has_credentials = any(
                    options.get(opt) for opt in CREDENTIAL_OPTIONS
                    if options.get(opt) and str(options.get(opt)).strip()
                )
                if not has_credentials:
                    return {
                        "status": "blocked",
                        "message": f"Login scanner '{module_name}' requires credentials. Set at least one of: USERNAME, PASSWORD, USER_FILE, PASS_FILE, or USERPASS_FILE.",
                        "module_name": module_name,
                    }

        return None

    def _wrap_tools(self, tools: List[StructuredTool]) -> List[StructuredTool]:
        seen_options: set[str] = set()
        failed_execution_signatures: set[tuple[str, str, str, str]] = set()
        failed_execution_retry_keys: set[tuple[str, str, str]] = set()
        failed_service_ports: set[tuple[str, int]] = set()
        module_valid_options: dict[str, set[str]] = {}
        seen_searches: set[str] = set()
        search_count = 0
        execution_attempts = 0
        wrapped_tools: List[StructuredTool] = []

        for tool in tools:
            original_tool = tool

            async def guarded_coroutine(_tool=original_tool, **kwargs):
                nonlocal execution_attempts, search_count
                call_kwargs = dict(kwargs or {})

                # Fix #1: Search loop detection
                if _tool.name in SEARCH_TOOL_NAMES:
                    search_term = str(call_kwargs.get("search_term", "")).strip().lower()

                    if search_term in seen_searches:
                        return json.dumps({
                            "status": "blocked",
                            "message": f"Already searched '{search_term}'. Use existing results or pivot to a different service/port.",
                        })

                    if search_count >= MAX_SEARCH_CALLS:
                        return json.dumps({
                            "status": "blocked",
                            "message": f"Search budget exceeded ({MAX_SEARCH_CALLS}). Act on available intel or conclude.",
                        })

                    seen_searches.add(search_term)
                    search_count += 1

                if _tool.name == "msf_get_module_options":
                    response = await _invoke_tool(_tool, call_kwargs)
                    result = normalize_tool_result(response)
                    module_key = metasploit_module_key(
                        call_kwargs.get("module_type"),
                        call_kwargs.get("module_name"),
                    )
                    if module_key and result.get("status") == "success":
                        seen_options.add(module_key)
                        # Fix #4: Cache valid option names for later validation
                        options_list = result.get("options", [])
                        valid_names = {
                            opt["name"] for opt in options_list
                            if isinstance(opt, dict) and "name" in opt
                        }
                        if valid_names:
                            module_valid_options[module_key] = valid_names
                    return response

                if _tool.name in EXECUTION_TOOL_NAMES:
                    module_type = "exploit" if _tool.name == "msf_run_exploit" else "auxiliary"
                    module_key = metasploit_module_key(module_type, call_kwargs.get("module_name"))
                    if module_key not in seen_options:
                        return json.dumps(
                            {
                                "status": "blocked",
                                "message": "Call msf_get_module_options before execution.",
                                "module_key": module_key,
                            }
                        )

                    validation_error = self._validate_execution_request(_tool.name, call_kwargs)
                    if validation_error is not None:
                        return json.dumps(validation_error)

                    # Fix #2: Service-level pivot enforcement
                    options = call_kwargs.get("options", {}) if isinstance(call_kwargs.get("options"), dict) else {}
                    exec_target = str(options.get("RHOSTS") or options.get("RHOST") or "").strip().lower()
                    exec_port = int(options.get("RPORT", 0) or 0)
                    if exec_target and exec_port and (exec_target, exec_port) in failed_service_ports:
                        return json.dumps({
                            "status": "blocked",
                            "message": f"An exploit already failed on {exec_target}:{exec_port}. Pivot to a different service/port.",
                        })

                    # Fix #4: Option validation against cached valid options
                    valid_options = module_valid_options.get(module_key, set())
                    if valid_options and options:
                        provided_options = set(options.keys())
                        invalid_options = provided_options - valid_options
                        if invalid_options:
                            return json.dumps({
                                "status": "blocked",
                                "message": f"Unknown options: {sorted(invalid_options)}. Check msf_get_module_options output for valid options.",
                                "valid_options_sample": sorted(list(valid_options))[:10],
                            })

                    execution_signature = _execution_signature(_tool.name, call_kwargs)
                    execution_retry_key = _execution_retry_key(_tool.name, call_kwargs)
                    if execution_retry_key in failed_execution_retry_keys:
                        module_type = "exploit" if _tool.name == "msf_run_exploit" else "auxiliary module"
                        return json.dumps(
                            {
                                "status": "blocked",
                                "message": f"This {module_type} already failed against this target in the current run. Pivot to a different path or gather new evidence first.",
                                "signature": list(execution_signature),
                            }
                        )

                    if execution_attempts >= self.max_attempts:
                        return json.dumps(
                            {
                                "status": "blocked",
                                "message": f"Execution attempt budget exceeded ({self.max_attempts}).",
                            }
                        )

                    target = _extract_target_from_execution_args(call_kwargs)
                    approved = require_manual_approval(
                        tool_name=_tool.name,
                        module_name=str(call_kwargs.get("module_name", "")),
                        target=target,
                        enabled=self.require_confirmation,
                    )
                    if not approved:
                        return json.dumps(
                            {
                                "status": "aborted",
                                "message": "Execution blocked pending manual approval.",
                                "tool": _tool.name,
                            }
                        )

                    execution_attempts += 1

                response = await _invoke_tool(_tool, call_kwargs)

                # Track failures for both exploit and auxiliary modules
                if _tool.name in EXECUTION_TOOL_NAMES:
                    result = normalize_tool_result(response)
                    is_failure = False

                    if _tool.name == "msf_run_exploit":
                        is_failure = (
                            result.get("status") == "error"
                            and not result.get("session_id")
                            and not result.get("session_id_detected")
                        )
                    elif _tool.name == "msf_run_auxiliary_module":
                        # Auxiliary modules fail if error status or no session created
                        module_output = str(result.get("module_output", "") or "")
                        is_failure = (
                            result.get("status") == "error"
                            or not result.get("session_id")
                            and not result.get("session_id_detected")
                            and "Error:" in module_output
                        )

                    if is_failure:
                        failed_execution_signatures.add(_execution_signature(_tool.name, call_kwargs))
                        failed_execution_retry_keys.add(_execution_retry_key(_tool.name, call_kwargs))

                        # Track failed service/port for pivot enforcement
                        fail_options = call_kwargs.get("options", {}) if isinstance(call_kwargs.get("options"), dict) else {}
                        fail_target = str(fail_options.get("RHOSTS") or fail_options.get("RHOST") or "").strip().lower()
                        fail_port = int(fail_options.get("RPORT", 0) or 0)
                        if fail_target and fail_port:
                            failed_service_ports.add((fail_target, fail_port))

                return response

            def guarded_func(_tool=original_tool, **kwargs):
                if _tool.func is None or inspect.iscoroutinefunction(_tool.func):
                    return json.dumps(
                        {
                            "status": "error",
                            "message": f"Tool {_tool.name} does not have a sync handler.",
                        }
                    )
                return _tool.func(**kwargs)

            wrapped_tools.append(
                StructuredTool(
                    name=original_tool.name,
                    description=original_tool.description,
                    args_schema=original_tool.args_schema,
                    func=guarded_func,
                    coroutine=guarded_coroutine,
                )
            )

        return wrapped_tools

    def _build_context(self, state: CyberState) -> str:
        targets_block = self._format_targets(state)
        web_block = self._format_web_findings(state)
        research_block = self._format_research_hints(state)
        attempts_block = self._format_prior_attempts(state)
        candidate_block = self._format_candidates(self._rank_candidates(state))

        return (
            f"MISSION: {state.get('mission_goal') or '(not specified)'}\n\n"
            f"TARGET INTELLIGENCE:\n{targets_block}\n\n"
            f"RELEVANT WEB FINDINGS:\n{web_block}\n\n"
            f"RESEARCH / OSINT HINTS:\n{research_block}\n\n"
            f"PRIOR EXPLOIT ATTEMPTS:\n{attempts_block}\n\n"
            f"CANDIDATE PATHS:\n{candidate_block}\n"
        )

    def _format_targets(self, state: CyberState) -> str:
        discovered_targets = state.get("discovered_targets", {}) or {}
        lines: List[str] = []

        for target, target_data in discovered_targets.items():
            os_guess = str(target_data.get("os_guess", "") or "unknown")
            lines.append(f"- TARGET {target}")
            lines.append(f"  OS hint: {os_guess}")

            services = _parse_services(target_data)
            if not services:
                lines.append("  Services: (none)")
                continue

            lines.append("  Services:")
            for service in services:
                version = f" ({service['version']})" if service["version"] else ""
                lines.append(f"    - {service['port']}/tcp {service['name']}{version}")

        return "\n".join(lines) if lines else "- none"

    def _format_web_findings(self, state: CyberState) -> str:
        lines: List[str] = []
        for finding in (state.get("web_findings", []) or [])[:10]:
            if not isinstance(finding, dict):
                continue
            path = finding.get("path") or finding.get("url") or ""
            code = finding.get("status_code", "?")
            interesting = bool(finding.get("is_interesting")) or code in {200, 301, 302, 403}
            if path and interesting:
                lines.append(f"- {code} {path}")
        return "\n".join(lines) if lines else "- none"

    def _format_research_hints(self, state: CyberState) -> str:
        hints: List[str] = []
        research_cache = state.get("research_cache", {}) or {}
        for key, value in list(research_cache.items())[:6]:
            hints.append(f"- Research ({key}): {value}")

        for finding in (state.get("intelligence_findings", []) or [])[:6]:
            if not isinstance(finding, dict):
                continue
            description = str(finding.get("description", "") or "")
            cve = str(finding.get("cve", "") or "")
            if not description and not cve:
                continue
            prefix = f"- OSINT [{cve}]" if cve else "- OSINT"
            hints.append(f"{prefix}: {description}".rstrip())

        return "\n".join(hints) if hints else "- none"

    def _format_prior_attempts(self, state: CyberState) -> str:
        attempts: List[str] = []
        for item in (state.get("exploited_services", []) or [])[-8:]:
            if not isinstance(item, dict):
                continue
            attempts.append(
                "- target={target} module={module} status={status} session={session}".format(
                    target=item.get("target", "?"),
                    module=item.get("module", "unknown"),
                    status=item.get("status", "unknown"),
                    session=item.get("session_id", "none"),
                )
            )
        return "\n".join(attempts) if attempts else "- none"

    def _rank_candidates(self, state: CyberState) -> List[Dict[str, Any]]:
        discovered_targets = state.get("discovered_targets", {}) or {}
        research_cache = state.get("research_cache", {}) or {}
        intelligence_findings = state.get("intelligence_findings", []) or []
        web_findings = state.get("web_findings", []) or []
        prior_attempts = state.get("exploited_services", []) or []

        candidates: List[Dict[str, Any]] = []
        for target, target_data in discovered_targets.items():
            services = _parse_services(target_data)
            for service in services:
                service_name = service["name"]
                version = service["version"].lower()
                service_intel = self._collect_service_intel(
                    research_cache=research_cache,
                    intelligence_findings=intelligence_findings,
                    service_name=service_name,
                    version=version,
                )
                if not self._service_is_metasploit_relevant(service_name, service_intel):
                    continue

                score = 0
                reasons: List[str] = []
                search_terms: List[str] = [service_name]

                if version:
                    score += 3
                    reasons.append("service version identified")
                    search_terms.append(version)

                if service_name.startswith("http"):
                    interesting_web = any(
                        isinstance(item, dict)
                        and (item.get("is_interesting") or item.get("status_code") in {200, 301, 302, 403})
                        for item in web_findings
                    )
                    if interesting_web:
                        score += 2
                        reasons.append("interesting web findings present")

                if service_intel["has_research"]:
                    score += 2
                    reasons.append("matching research hint found")
                if service_intel["has_version_research"]:
                    score += 2
                    reasons.append("version-specific research hint found")

                if service_intel["has_osint"]:
                    score += 2
                    reasons.append("matching OSINT finding found")
                if service_intel["has_version_osint"]:
                    score += 2
                    reasons.append("version-specific OSINT finding found")

                same_service_failed = any(
                    isinstance(item, dict)
                    and item.get("target") == target
                    and self._attempt_matches_service(service_name, item)
                    and str(item.get("status", "")).lower() not in {"success", "opened", "succeeded"}
                    for item in prior_attempts
                )
                if same_service_failed:
                    score -= 2
                    reasons.append("prior attempt for this service path already failed")

                path_type = self._path_type_for_service(service_name)
                if path_type == "auxiliary":
                    search_terms.append(f"{service_name}_login")

                search_terms.extend(service_intel["cves"])

                candidates.append(
                    {
                        "target": target,
                        "service": service_name,
                        "port": service["port"],
                        "path_type": path_type,
                        "score": score,
                        "reasons": reasons[:3],
                        "search_terms": self._dedupe_terms(search_terms)[:4],
                    }
                )

        candidates.sort(key=lambda item: item["score"], reverse=True)
        return candidates[:3]

    def _format_candidates(self, candidates: List[Dict[str, Any]]) -> str:
        if not candidates:
            return "- none"

        lines: List[str] = []
        for candidate in candidates:
            reasons = "; ".join(candidate["reasons"]) or "limited evidence"
            search_terms = ", ".join(candidate["search_terms"]) or "none"
            lines.append(
                f"- {candidate['target']} {candidate['service']}/{candidate['port']} "
                f"[{candidate['path_type']}] score={candidate['score']} "
                f"| reasons: {reasons} | search_terms: {search_terms}"
            )
        return "\n".join(lines)

    def _service_is_metasploit_relevant(self, service_name: str, service_intel: Dict[str, Any]) -> bool:
        if service_name in METASPLOIT_DEFAULT_SERVICES:
            return True
        return bool(service_intel.get("suggests_metasploit"))

    def _path_type_for_service(self, service_name: str) -> str:
        if service_name in {"ssh", "ftp", "smb", "telnet", "mysql", "postgresql", "mssql", "redis", "vnc", "rdp"}:
            return "auxiliary"
        return "exploit"

    def _collect_service_intel(
        self,
        research_cache: Dict[str, Any],
        intelligence_findings: List[Dict[str, Any]],
        service_name: str,
        version: str,
    ) -> Dict[str, Any]:
        indicators = {"metasploit", "msf", "exploit/"}
        has_research = False
        has_version_research = False
        has_osint = False
        has_version_osint = False
        suggests_metasploit = False
        cves: List[str] = []

        for key, value in research_cache.items():
            text = f"{key} {value}".lower()
            if service_name and service_name in text:
                has_research = True
            if version and version in text:
                has_version_research = True
            if (
                (service_name and service_name in text) or
                (version and version in text)
            ) and any(indicator in text for indicator in indicators):
                suggests_metasploit = True

        for item in intelligence_findings:
            if not isinstance(item, dict):
                continue
            text = json.dumps(item, default=str).lower()
            matches_service = (service_name and service_name in text) or (version and version in text)
            if not matches_service:
                continue
            if service_name and service_name in text:
                has_osint = True
            if version and version in text:
                has_version_osint = True

            msf_module = item.get("data", {}).get("msf_module", "") if isinstance(item.get("data"), dict) else ""
            if msf_module or any(indicator in text for indicator in indicators):
                suggests_metasploit = True

            cve = str(item.get("cve", "")).strip().lower()
            if cve:
                cves.append(cve)

        return {
            "has_research": has_research,
            "has_version_research": has_version_research,
            "has_osint": has_osint,
            "has_version_osint": has_version_osint,
            "suggests_metasploit": suggests_metasploit,
            "cves": self._dedupe_terms(cves)[:2],
        }

    def _extract_matching_cves(
        self,
        intelligence_findings: List[Dict[str, Any]],
        service_name: str,
        version: str,
    ) -> List[str]:
        cves: List[str] = []
        for item in intelligence_findings:
            if not isinstance(item, dict):
                continue
            text = json.dumps(item, default=str).lower()
            if (service_name and service_name in text) or (version and version in text):
                cve = str(item.get("cve", "")).strip()
                if cve:
                    cves.append(cve.lower())
        return cves[:2]

    def _attempt_matches_service(self, service_name: str, attempt: Dict[str, Any]) -> bool:
        module = str(attempt.get("module", "")).lower()

        if service_name.startswith("http"):
            return any(token in module for token in {"http", "apache", "tomcat", "nginx", "web"})
        if service_name == "ssh":
            return "ssh" in module
        if service_name == "ftp":
            return "ftp" in module
        if service_name == "smb":
            return "smb" in module or "samba" in module
        return service_name in module

    def _dedupe_terms(self, values: List[str]) -> List[str]:
        seen = set()
        deduped: List[str] = []
        for value in values:
            normalized = str(value or "").strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(normalized)
        return deduped

    def _extract_updates(self, messages: List[Any], state: CyberState) -> Dict[str, Any]:
        discovered_targets = state.get("discovered_targets", {}) or {}
        default_target = next(iter(discovered_targets.keys()), "unknown")

        last_execution: Dict[str, Any] = {}
        verified_sessions: Dict[str, Any] = {}

        for message in messages:
            if not isinstance(message, ToolMessage):
                continue

            data = normalize_tool_result(message.content)
            if not data:
                continue

            if message.name in EXECUTION_TOOL_NAMES:
                options = data.get("options", {}) if isinstance(data.get("options"), dict) else {}
                target = options.get("RHOSTS") or options.get("RHOST") or default_target
                last_execution = {
                    "target": target,
                    "module": data.get("module", data.get("module_name", "unknown")),
                    "status": data.get("status", "unknown"),
                    "session_id": data.get("session_id") or data.get("session_id_detected"),
                    "timestamp": datetime.now().isoformat(),
                }

            if message.name == "msf_list_active_sessions":
                if data.get("status") == "success" and isinstance(data.get("sessions"), dict):
                    verified_sessions = data.get("sessions", {})

        session_id = last_execution.get("session_id")
        if session_id is not None:
            session_key = str(session_id)
            if not verified_sessions or session_key not in verified_sessions:
                session_id = None
                last_execution["session_id"] = None

        updates: Dict[str, Any] = {
            "current_agent": "striker",
            "iteration_count": state.get("iteration_count", 0) + 1,
            "agent_log": [
                AgentLogEntry(
                    agent="striker",
                    action="run_exploit",
                    target=last_execution.get("target", default_target),
                    findings=last_execution or None,
                    reasoning="Metasploit striker run complete.",
                )
            ],
        }

        if last_execution:
            updates["exploited_services"] = [
                *state.get("exploited_services", []),
                last_execution,
            ]

        if session_id is not None:
            target = last_execution.get("target", default_target)
            updates["active_sessions"] = {
                **state.get("active_sessions", {}),
                target: {
                    "session_id": session_id,
                    "module": last_execution.get("module", "unknown"),
                    "established_at": datetime.now().isoformat(),
                },
            }
            updates["critical_findings"] = [
                f"Session {session_id} opened on {target} via {last_execution.get('module', 'unknown')}"
            ]

        return updates

    def _error_update(
        self,
        state: CyberState,
        error_type: str,
        message: str,
        recoverable: bool,
    ) -> Dict[str, Any]:
        return {
            "current_agent": "striker",
            "iteration_count": state.get("iteration_count", 0) + 1,
            "errors": [
                AgentError(
                    agent="striker",
                    error_type=error_type,
                    error=message,
                    recoverable=recoverable,
                )
            ],
        }


def _build_striker_context(state: CyberState) -> str:
    """Compatibility wrapper used by tests and ad-hoc debugging."""
    return StrikerAgent()._build_context(state)


async def striker_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper for the Striker agent."""
    updates = await StrikerAgent().call_llm(state)
    persist_state_update(state, updates)
    return updates
