"""Pure Striker domain logic shared by the old and new execution paths."""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.skills import match_skills, render_skill_matches
from src.utils.agent_runtime import collect_reasoning_chunks, iter_tool_messages
from src.utils.approval import derive_command_target, require_manual_approval
from src.utils.parsers import metasploit_module_key, normalize_tool_result
from src.utils.tools import BaseToolPolicy, RuntimeTool, ToolInterception

STRIKER_ALLOWED_TOOLS = {
    "msf_search_modules",
    "msf_get_module_info",
    "msf_get_module_options",
    "msf_run_exploit",
    "msf_run_auxiliary",
    "msf_list_sessions",
    "web_sqlmap_scan",
    "access_hydra_attack",
    "access_smb_enum",
    "web_wordpress_scan",
    "system_execute_command",
}
STRIKER_REQUIRE_CONFIRMATION = os.getenv("STRIKER_REQUIRE_CONFIRMATION", "true").lower() == "true"
MAX_EXPLOIT_ATTEMPTS = int(os.getenv("STRIKER_MAX_EXPLOIT_ATTEMPTS", "3"))
MAX_SEARCH_CALLS = int(os.getenv("STRIKER_MAX_SEARCH_CALLS", "6"))
EXECUTION_TOOL_NAMES = {"msf_run_exploit", "msf_run_auxiliary"}
SEARCH_TOOL_NAMES = {"msf_search_modules"}
MODULE_INSPECTION_TOOL_NAMES = {"msf_get_module_info", "msf_get_module_options"}
KALI_TOOL_NAMES = {
    "web_sqlmap_scan",
    "access_hydra_attack",
    "access_smb_enum",
    "web_wordpress_scan",
    "system_execute_command",
}
KALI_APPROVAL_TOOLS = {"web_sqlmap_scan", "access_hydra_attack", "system_execute_command"}
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


def dedupe_terms(values: List[str]) -> List[str]:
    """Preserve order while removing empty or duplicate string values."""

    seen = set()
    deduped: List[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return deduped


def parse_services(target_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize discovered target services into a predictable list for scoring and prompt rendering."""

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


def extract_target_from_execution_args(kwargs: Dict[str, Any]) -> str:
    """Resolve the target host from Metasploit-style execution arguments."""

    options = kwargs.get("options", {}) if isinstance(kwargs.get("options"), dict) else {}
    target = options.get("RHOSTS") or options.get("RHOST") or options.get("TARGET")
    return str(target or "unknown")


def execution_signature(tool_name: str, kwargs: Dict[str, Any]) -> tuple[str, str, str, str]:
    """Build a detailed execution signature used for per-path tracking."""

    options = kwargs.get("options", {}) if isinstance(kwargs.get("options"), dict) else {}
    return (
        tool_name,
        str(kwargs.get("module_name", "") or "").strip().lower(),
        extract_target_from_execution_args(kwargs).strip().lower(),
        f"{str(options.get('RPORT', '') or '').strip()}:{str(options.get('TARGETURI') or options.get('TARGETPATH') or options.get('URI') or options.get('PATH') or '').strip()}",
    )


def execution_retry_key(tool_name: str, kwargs: Dict[str, Any]) -> tuple[str, str, str]:
    """Build the coarse retry key used to block repeated failed paths."""

    return (
        tool_name,
        str(kwargs.get("module_name", "") or "").strip().lower(),
        extract_target_from_execution_args(kwargs).strip().lower(),
    )


def normalize_option_map(raw: Any) -> Dict[str, Any]:
    """Accept either dict or comma-separated option strings and normalize them to a dict."""

    if isinstance(raw, dict):
        return dict(raw)
    if not isinstance(raw, str):
        return {}
    options: Dict[str, Any] = {}
    for item in raw.split(","):
        key, sep, value = item.partition("=")
        if sep and key.strip():
            options[key.strip()] = value.strip()
    return options


def decode_tool_payload(raw: Any) -> Any:
    """Decode a tool payload that might already be parsed or still be a JSON string."""

    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return {}


def extract_tool_field(payload: Dict[str, Any], key: str, default: Any = None) -> Any:
    """Read a value from direct, evidence, or raw tool payload locations."""

    for container in (
        payload,
        payload.get("evidence") if isinstance(payload.get("evidence"), dict) else None,
        payload.get("raw") if isinstance(payload.get("raw"), dict) else None,
    ):
        if isinstance(container, dict) and key in container:
            return container.get(key)
    return default


def extract_tool_invocation(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Read invocation metadata from common normalized tool payload shapes."""

    for container in (
        payload,
        payload.get("metadata") if isinstance(payload.get("metadata"), dict) else None,
        payload.get("raw") if isinstance(payload.get("raw"), dict) else None,
    ):
        if isinstance(container, dict):
            invocation = container.get("invocation")
            if isinstance(invocation, dict):
                return invocation
    return {}


def extract_tool_validation(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Read normalized validation metadata from tool payloads."""

    validation = payload.get("validation")
    if isinstance(validation, dict):
        return validation
    return {}


def is_invalid_callback_host(value: str) -> bool:
    """Reject loopback or empty callback hosts for reverse payloads."""

    host = str(value or "").strip().lower()
    if not host or host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _format_targets(state) -> str:
    """Render discovered targets and services into compact prompt text."""

    lines: List[str] = []
    for target, target_data in (state.get("discovered_targets", {}) or {}).items():
        lines.append(f"- TARGET {target}")
        lines.append(f"  OS hint: {str(target_data.get('os_guess', '') or 'unknown')}")
        services = parse_services(target_data)
        if not services:
            lines.append("  Services: (none)")
            continue
        lines.append("  Services:")
        for service in services:
            version = f" ({service['version']})" if service["version"] else ""
            lines.append(f"    - {service['port']}/tcp {service['name']}{version}")
    return "\n".join(lines) if lines else "- none"


def _format_web_findings(state) -> str:
    """Render only the most relevant web findings for exploitation decisions."""

    lines = []
    for finding in (state.get("web_findings", []) or [])[:10]:
        if not isinstance(finding, dict):
            continue
        path = finding.get("path") or finding.get("url") or ""
        code = finding.get("status_code", "?")
        if not path:
            continue
        if finding.get("source_tool") == "gobuster":
            raw_finding = str(finding.get("raw_finding", "") or "").strip()
            if raw_finding:
                lines.append(f"- {raw_finding}")
                continue
        if code in {0, "0", None, ""}:
            rationale = str(finding.get("rationale", "") or "").strip()
            if rationale.lower().startswith("nikto finding:"):
                rationale = rationale.split(":", 1)[1].strip()
            if finding.get("is_interesting") and rationale:
                lines.append(f"- {path}: {rationale}")
            continue
        if finding.get("is_interesting") or code in {200, 301, 302, 403}:
            lines.append(f"- {code} {path}")
    return "\n".join(lines) if lines else "- none"


def _format_research_hints(state) -> str:
    """Render cached research and intelligence hints into compact prompt text."""

    hints: List[str] = []
    for key, value in list((state.get("research_cache", {}) or {}).items())[:6]:
        hints.append(f"- Research ({key}): {value}")
    for finding in (state.get("intelligence_findings", []) or [])[:6]:
        if not isinstance(finding, dict):
            continue
        description = str(finding.get("description", "") or "")
        cve = str(finding.get("cve", "") or "")
        if description or cve:
            label = "OSINT" if finding.get("is_osint_derived") and finding.get("source_types") == ["osint"] else "Intel"
            hints.append(f"{'- ' + label + ' [' + cve + ']' if cve else '- ' + label}: {description}".rstrip())
    return "\n".join(hints) if hints else "- none"


def _format_prior_attempts(state) -> str:
    """Render recent exploitation history so striker can avoid repeating failures."""

    attempts: List[str] = []
    for item in (state.get("exploited_services", []) or [])[-8:]:
        if isinstance(item, dict):
            attempts.append(
                "- target={target} module={module} status={status} session={session}".format(
                    target=item.get("target", "?"),
                    module=item.get("module", "unknown"),
                    status=item.get("status", "unknown"),
                    session=item.get("session_id", "none"),
                )
            )
    return "\n".join(attempts) if attempts else "- none"


def _collect_service_intel(
    research_cache: Dict[str, Any],
    intelligence_findings: List[Dict[str, Any]],
    service_name: str,
    version: str,
) -> Dict[str, Any]:
    """Collect research and intelligence indicators that strengthen a service-specific path."""

    indicators = {"metasploit", "msf", "exploit/"}
    has_research = has_version_research = has_intelligence = has_version_intelligence = suggests_metasploit = False
    cves: List[str] = []
    for key, value in research_cache.items():
        text = f"{key} {value}".lower()
        has_research = has_research or (service_name in text if service_name else False)
        has_version_research = has_version_research or (version in text if version else False)
        if ((service_name and service_name in text) or (version and version in text)) and any(indicator in text for indicator in indicators):
            suggests_metasploit = True
    for item in intelligence_findings:
        if not isinstance(item, dict):
            continue
        text = json.dumps(item, default=str).lower()
        if not ((service_name and service_name in text) or (version and version in text)):
            continue
        has_intelligence = has_intelligence or (service_name in text if service_name else False)
        has_version_intelligence = has_version_intelligence or (version in text if version else False)
        if (isinstance(item.get("data"), dict) and item.get("data", {}).get("msf_module")) or any(indicator in text for indicator in indicators):
            suggests_metasploit = True
        cve = str(item.get("cve", "")).strip().lower()
        if cve:
            cves.append(cve)
    return {
        "has_research": has_research,
        "has_version_research": has_version_research,
        "has_intelligence": has_intelligence,
        "has_version_intelligence": has_version_intelligence,
        "suggests_metasploit": suggests_metasploit,
        "cves": dedupe_terms(cves)[:2],
    }


def _attempt_matches_service(service_name: str, attempt: Dict[str, Any]) -> bool:
    """Approximate whether a prior attempt corresponds to the same service family."""

    module = str(attempt.get("module", "")).lower()
    if service_name.startswith("http"):
        return any(token in module for token in {"http", "apache", "tomcat", "nginx", "web"})
    if service_name == "smb":
        return "smb" in module or "samba" in module
    return service_name in module


def _rank_candidates(state) -> List[Dict[str, Any]]:
    """Rank a small set of candidate exploitation paths from current evidence."""

    discovered_targets = state.get("discovered_targets", {}) or {}
    research_cache = state.get("research_cache", {}) or {}
    intelligence_findings = state.get("intelligence_findings", []) or []
    web_findings = state.get("web_findings", []) or []
    prior_attempts = state.get("exploited_services", []) or []
    candidates: List[Dict[str, Any]] = []

    # Candidate scoring is intentionally simple: service/version evidence plus research/intelligence hints.
    for target, target_data in discovered_targets.items():
        for service in parse_services(target_data):
            intel = _collect_service_intel(research_cache, intelligence_findings, service["name"], service["version"].lower())
            if service["name"] not in METASPLOIT_DEFAULT_SERVICES and not intel["suggests_metasploit"]:
                continue
            search_terms = [service["name"], service["version"].lower(), *intel["cves"]]
            score = (3 if service["version"] else 0) + (2 if intel["has_research"] else 0) + (2 if intel["has_version_research"] else 0)
            score += (2 if intel["has_intelligence"] else 0) + (2 if intel["has_version_intelligence"] else 0)
            reasons = ["service version identified"] if service["version"] else []
            if intel["has_research"]:
                reasons.append("matching research hint found")
            if intel["has_intelligence"]:
                reasons.append("matching intelligence finding found")
            if service["name"].startswith("http") and any(isinstance(item, dict) and (item.get("is_interesting") or item.get("status_code") in {200, 301, 302, 403}) for item in web_findings):
                score += 2
                reasons.append("interesting web findings present")
            if any(isinstance(item, dict) and item.get("target") == target and _attempt_matches_service(service["name"], item) and str(item.get("status", "")).lower() not in {"success", "opened", "succeeded"} for item in prior_attempts):
                score -= 2
                reasons.append("prior attempt for this service path already failed")
            candidates.append(
                {
                    "target": target,
                    "service": service["name"],
                    "port": service["port"],
                    "path_type": "auxiliary" if service["name"] in {"ssh", "ftp", "smb", "telnet", "mysql", "postgresql", "mssql", "redis", "vnc", "rdp"} else "exploit",
                    "score": score,
                    "reasons": reasons[:3],
                    "search_terms": dedupe_terms([term for term in search_terms if term])[:4],
                }
            )
    candidates.sort(key=lambda item: item["score"], reverse=True)
    return candidates[:3]


def _format_candidates(candidates: List[Dict[str, Any]]) -> str:
    """Render ranked candidate paths for the system prompt."""

    if not candidates:
        return "- none"
    lines = []
    for candidate in candidates:
        lines.append(
            f"- {candidate['target']} {candidate['service']}/{candidate['port']} [{candidate['path_type']}] "
            f"score={candidate['score']} | reasons: {'; '.join(candidate['reasons']) or 'limited evidence'} "
            f"| search_terms: {', '.join(candidate['search_terms']) or 'none'}"
        )
    return "\n".join(lines)


def build_striker_context(state) -> str:
    """Build the full exploitation context block shown to striker."""

    skill_matches = match_skills(state, "striker", limit=2)
    skills_block = render_skill_matches(skill_matches)
    skills_section = f"RELEVANT SKILLS:\n{skills_block}\n\n" if skills_block else ""
    return (
        f"MISSION: {state.get('mission_goal') or '(not specified)'}\n\n"
        f"TARGET INTELLIGENCE:\n{_format_targets(state)}\n\n"
        f"RELEVANT WEB FINDINGS:\n{_format_web_findings(state)}\n\n"
        f"RESEARCH / INTELLIGENCE HINTS:\n{_format_research_hints(state)}\n\n"
        f"{skills_section}"
        f"PRIOR EXPLOIT ATTEMPTS:\n{_format_prior_attempts(state)}\n\n"
        f"CANDIDATE PATHS:\n{_format_candidates(_rank_candidates(state))}\n"
    )


def _build_striker_context(state) -> str:
    return build_striker_context(state)


@dataclass
class ToolGuardState:
    seen_options: set[str] = field(default_factory=set)
    module_valid_options: dict[str, set[str]] = field(default_factory=dict)
    seen_searches: set[str] = field(default_factory=set)
    failed_execution_retry_keys: set[tuple[str, str, str]] = field(default_factory=set)
    failed_service_ports: set[tuple[str, int]] = field(default_factory=set)
    search_count: int = 0
    execution_attempts: int = 0


def validate_execution_request(tool_name: str, kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if tool_name == "msf_run_exploit":
        payload_name = str(kwargs.get("payload_name", "") or "").strip().lower()
        if "reverse" in payload_name:
            payload_options = normalize_option_map(kwargs.get("payload_options"))
            lhost = str(payload_options.get("LHOST", "") or "").strip()
            if is_invalid_callback_host(lhost):
                return {
                    "status": "blocked",
                    "message": "Reverse payload requires a reachable non-loopback LHOST.",
                    "payload_name": kwargs.get("payload_name", ""),
                    "payload_options": payload_options,
                }
    if tool_name == "msf_run_auxiliary":
        module_name = str(kwargs.get("module_name", "") or "").strip().lower()
        if any(cred_module in module_name for cred_module in CREDENTIAL_MODULES):
            options = kwargs.get("options", {}) if isinstance(kwargs.get("options"), dict) else {}
            if not any(options.get(opt) and str(options.get(opt)).strip() for opt in CREDENTIAL_OPTIONS):
                return {
                    "status": "blocked",
                    "message": f"Login scanner '{module_name}' requires credentials. Set at least one of: USERNAME, PASSWORD, USER_FILE, PASS_FILE, or USERPASS_FILE.",
                    "module_name": module_name,
                }
    return None


class StrikerToolPolicy(BaseToolPolicy):
    def __init__(self, *, require_confirmation: bool, max_attempts: int):
        """Track search/execution budgets and enforce approval plus retry guardrails."""

        self.guard = ToolGuardState()
        self.require_confirmation = require_confirmation
        self.max_attempts = max_attempts

    async def before_call(self, tool: RuntimeTool, arguments: dict[str, Any]) -> ToolInterception | None:
        """Block unsafe or wasteful actions before the tool executes."""

        for guard in (self._guard_search_budget, self._guard_kali_execution, self._guard_msf_execution):
            blocked = guard(tool.name, arguments)
            if blocked is not None:
                return ToolInterception(blocked)
        return None

    async def after_call(self, tool: RuntimeTool, arguments: dict[str, Any], raw_result: Any) -> Any:
        """Remember module options and failed paths after tool execution."""

        if tool.name == "msf_get_module_options":
            self._remember_module_options(arguments, raw_result)
        else:
            self._record_msf_execution_result(tool.name, arguments, raw_result)
        return raw_result

    def _guard_search_budget(self, tool_name: str, call_kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Prevent repeated or excessive Metasploit search calls."""

        if tool_name not in SEARCH_TOOL_NAMES:
            return None
        search_term = str(call_kwargs.get("search_term", "")).strip().lower()
        if search_term in self.guard.seen_searches:
            return {"status": "blocked", "message": f"Already searched '{search_term}'. Use existing results or pivot to a different service/port."}
        if self.guard.search_count >= MAX_SEARCH_CALLS:
            return {"status": "blocked", "message": f"Search budget exceeded ({MAX_SEARCH_CALLS}). Act on available intel or conclude."}
        self.guard.seen_searches.add(search_term)
        self.guard.search_count += 1
        return None

    def _guard_kali_execution(self, tool_name: str, call_kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Require approval for the higher-impact attackbox actions."""

        if tool_name not in KALI_APPROVAL_TOOLS:
            return None
        module_label = str(call_kwargs.get("service") or call_kwargs.get("additional_args") or "").strip()
        if tool_name == "system_execute_command":
            module_label = "shell-command"
        approved = require_manual_approval(
            tool_name=tool_name,
            module_name=module_label,
            target=str(
                call_kwargs.get("target")
                or call_kwargs.get("url")
                or (derive_command_target(str(call_kwargs.get("command") or "")) if tool_name == "system_execute_command" else "")
                or "unknown"
            ),
            action=str(call_kwargs.get("command") or ""),
            enabled=self.require_confirmation,
        )
        return None if approved else {"status": "aborted", "message": "Execution blocked pending manual approval.", "tool": tool_name}

    def _remember_module_options(self, call_kwargs: Dict[str, Any], response: Any) -> None:
        """Cache the valid option names for a module after msf_get_module_options."""

        result = normalize_tool_result(response)
        module_key = metasploit_module_key(call_kwargs.get("module_type"), call_kwargs.get("module_name"))
        if not module_key or result.get("status") != "success":
            return
        self.guard.seen_options.add(module_key)
        valid_names = {opt["name"] for opt in result.get("options", []) if isinstance(opt, dict) and "name" in opt}
        if valid_names:
            self.guard.module_valid_options[module_key] = valid_names

    def _guard_msf_execution(self, tool_name: str, call_kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enforce option inspection, retry controls, and approval before Metasploit execution."""

        if tool_name not in EXECUTION_TOOL_NAMES:
            return None
        module_type = "exploit" if tool_name == "msf_run_exploit" else "auxiliary"
        module_key = metasploit_module_key(module_type, call_kwargs.get("module_name"))
        if module_key not in self.guard.seen_options:
            return {"status": "blocked", "message": "Call msf_get_module_options before execution.", "module_key": module_key}
        validation_error = validate_execution_request(tool_name, call_kwargs)
        if validation_error is not None:
            return validation_error

        options = call_kwargs.get("options", {}) if isinstance(call_kwargs.get("options"), dict) else {}
        exec_target = str(options.get("RHOSTS") or options.get("RHOST") or "").strip().lower()
        exec_port = int(options.get("RPORT", 0) or 0)
        if exec_target and exec_port and (exec_target, exec_port) in self.guard.failed_service_ports:
            return {"status": "blocked", "message": f"An exploit already failed on {exec_target}:{exec_port}. Pivot to a different service/port."}

        valid_options = self.guard.module_valid_options.get(module_key, set())
        if valid_options and options:
            invalid_options = set(options) - valid_options
            if invalid_options:
                return {"status": "blocked", "message": f"Unknown options: {sorted(invalid_options)}. Check msf_get_module_options output for valid options.", "valid_options_sample": sorted(list(valid_options))[:10]}

        retry_key = execution_retry_key(tool_name, call_kwargs)
        if retry_key in self.guard.failed_execution_retry_keys:
            module_label = "exploit" if tool_name == "msf_run_exploit" else "auxiliary module"
            return {"status": "blocked", "message": f"This {module_label} already failed against this target in the current run. Pivot to a different path or gather new evidence first.", "signature": list(execution_signature(tool_name, call_kwargs))}
        if self.guard.execution_attempts >= self.max_attempts:
            return {"status": "blocked", "message": f"Execution attempt budget exceeded ({self.max_attempts})."}

        approved = require_manual_approval(
            tool_name=tool_name,
            module_name=str(call_kwargs.get("module_name", "")),
            target=extract_target_from_execution_args(call_kwargs),
            enabled=self.require_confirmation,
        )
        if not approved:
            return {"status": "aborted", "message": "Execution blocked pending manual approval.", "tool": tool_name}
        self.guard.execution_attempts += 1
        return None

    def _record_msf_execution_result(self, tool_name: str, call_kwargs: Dict[str, Any], response: Any) -> None:
        """Record failed execution paths so the model has to pivot meaningfully."""

        if tool_name not in EXECUTION_TOOL_NAMES:
            return
        result = normalize_tool_result(response)
        if tool_name == "msf_run_exploit":
            is_failure = result.get("status") == "error" and not result.get("session_id") and not result.get("session_id_detected")
        else:
            module_output = str(result.get("module_output", "") or "")
            is_failure = result.get("status") == "error" or (not result.get("session_id") and not result.get("session_id_detected") and "Error:" in module_output)
        if not is_failure:
            return
        self.guard.failed_execution_retry_keys.add(execution_retry_key(tool_name, call_kwargs))
        options = call_kwargs.get("options", {}) if isinstance(call_kwargs.get("options"), dict) else {}
        target = str(options.get("RHOSTS") or options.get("RHOST") or "").strip().lower()
        port = int(options.get("RPORT", 0) or 0)
        if target and port:
            self.guard.failed_service_ports.add((target, port))


def extract_striker_updates(
    messages: List[dict[str, Any]],
    state,
    context: str,
    *,
    matched_skill_names: List[str] | None,
    current_agent: str,
    base_update: dict[str, Any],
    log_action_payload: dict[str, Any],
) -> Dict[str, Any]:
    """Interpret tool-loop messages into striker-specific state updates."""

    discovered_targets = state.get("discovered_targets", {}) or {}
    default_target = next(iter(discovered_targets.keys()), "unknown")
    last_execution: Dict[str, Any] = {}
    verified_sessions: Dict[str, Any] = {}
    search_terms: List[str] = []
    matched_terms: List[str] = []
    candidate_modules: List[str] = []
    selected_module = ""
    stop_reason = ""
    module_inspection_failed = False
    module_inspection_error = ""
    reasoning = "\n\n".join(chunk for chunk in collect_reasoning_chunks(messages) if chunk).strip()
    saw_tool_activity = False
    collected_artifacts: List[Dict[str, Any]] = []

    # Walk every tool result once and collect execution, session, artifact, and reasoning evidence.
    for message, normalized in iter_tool_messages(messages):
        saw_tool_activity = True
        data = normalized or decode_tool_payload(message.get("content"))
        if not isinstance(data, dict):
            data = {}
        name = str(message.get("name", "") or "")
        invocation = extract_tool_invocation(data)

        if name == "msf_search_modules":
            term = str(invocation.get("search_term", "") or "").strip()
            if term:
                search_terms.append(term)
                matched_terms.append(term)
            results = extract_tool_field(data, "result", None)
            if not isinstance(results, list):
                results = extract_tool_field(data, "results", [])
            for item in results if isinstance(results, list) else []:
                normalized_item = str(item or "").strip()
                if normalized_item:
                    candidate_modules.append(normalized_item)
            continue

        if name in MODULE_INSPECTION_TOOL_NAMES:
            module_name = str(invocation.get("module_name", "") or "").strip()
            if module_name:
                selected_module = module_name
            if str(data.get("status", "") or "").lower() == "error":
                module_inspection_failed = True
                raw_message = extract_tool_field(data, "message", "") or data.get("summary") or ""
                detail = str(raw_message or f"{name} failed").strip()
                module_label = module_name or selected_module or "unknown module"
                module_inspection_error = (
                    f"Metasploit module introspection failed for {module_label}: {detail}"
                )
        for artifact in data.get("artifacts", []) if isinstance(data.get("artifacts"), list) else []:
            if isinstance(artifact, dict):
                collected_artifacts.append(artifact)

        if name in EXECUTION_TOOL_NAMES:
            options = extract_tool_field(data, "options", {})
            if not isinstance(options, dict):
                options = {}
            target = options.get("RHOSTS") or options.get("RHOST") or invocation.get("target") or invocation.get("url") or default_target
            module_name = (
                extract_tool_field(data, "module", "")
                or extract_tool_field(data, "module_name", "")
                or invocation.get("module_name")
                or selected_module
                or "unknown"
            )
            selected_module = str(module_name)
            last_execution = {
                "target": str(target),
                "module": str(module_name),
                "executed_tool": name,
                "executed_module": str(module_name),
                "tool_status": str(data.get("status", "unknown") or "unknown"),
                "session_id": extract_tool_field(data, "session_id") or extract_tool_field(data, "session_id_detected"),
                "timestamp": datetime.now().isoformat(),
            }
            raw_message = extract_tool_field(data, "message", "") or data.get("summary") or ""
            if str(raw_message or "").strip():
                stop_reason = str(raw_message).strip()
        elif name in KALI_TOOL_NAMES:
            target = invocation.get("target") or invocation.get("url") or invocation.get("command") or default_target
            status = data.get("status")
            if status is None and "success" in data:
                status = "success" if data.get("success") else "error"
            validation = extract_tool_validation(data)
            last_execution = {
                "target": str(target),
                "module": name,
                "executed_tool": name,
                "executed_module": None,
                "tool_status": str(status or "unknown"),
                "session_id": None,
                "validation_outcome": str(validation.get("outcome", "inconclusive") or "inconclusive"),
                "validation_reason": str(validation.get("reason", "") or ""),
                "timestamp": datetime.now().isoformat(),
            }
            raw_message = extract_tool_field(data, "message", "") or data.get("summary") or ""
            if str(raw_message or "").strip():
                stop_reason = str(raw_message).strip()
            if (
                last_execution.get("validation_reason")
                and str(last_execution.get("validation_outcome", "")).lower() != "positive"
            ):
                stop_reason = str(last_execution.get("validation_reason") or stop_reason)

        # Session validation is authoritative; module success without a session is not enough.
        sessions = extract_tool_field(data, "sessions", {})
        if name == "msf_list_sessions" and data.get("status") == "success" and isinstance(sessions, dict):
            verified_sessions = sessions

    session_id = last_execution.get("session_id")
    session_opened = bool(session_id is not None and verified_sessions and str(session_id) in verified_sessions)
    if session_id is not None and not session_opened:
        last_execution["session_id"] = None
        session_id = None

    if module_inspection_failed:
        pivot_reason = module_inspection_error or "Metasploit module introspection failed."
        if last_execution and last_execution.get("executed_tool") in KALI_TOOL_NAMES:
            pivot_reason = f"{pivot_reason} Pivoted to fallback validation after introspection failed."
        if pivot_reason and pivot_reason not in reasoning:
            reasoning = f"{reasoning}\n\n{pivot_reason}".strip() if reasoning else pivot_reason

    if not stop_reason and module_inspection_failed:
        stop_reason = module_inspection_error
    if stop_reason and stop_reason not in reasoning:
        reasoning = f"{reasoning}\n\n{stop_reason}".strip() if reasoning else stop_reason
    if not last_execution and saw_tool_activity and not stop_reason:
        stop_reason = "No acceptable Metasploit module matched current evidence."
        reasoning = f"{reasoning}\n\n{stop_reason}".strip() if reasoning else stop_reason
    if context and "TARGET INTELLIGENCE:" not in reasoning:
        reasoning = f"{reasoning}\n\n{context}".strip() if reasoning else context

    findings_status = "no_candidate"
    execution_status = str(last_execution.get("tool_status", "") or "").lower()
    used_kali_fallback = bool(last_execution and last_execution.get("executed_tool") in KALI_TOOL_NAMES)
    validation_outcome = str(last_execution.get("validation_outcome", "") or "").lower()
    if last_execution:
        if execution_status == "aborted" or "manual approval" in stop_reason.lower():
            findings_status = "approval_blocked"
        elif session_opened:
            findings_status = "session_opened"
        elif module_inspection_failed and used_kali_fallback:
            findings_status = "execution_error"
        elif used_kali_fallback and validation_outcome == "positive":
            findings_status = "validated_no_session"
        elif used_kali_fallback and execution_status in {"success", "warning"}:
            findings_status = "no_candidate"
        elif execution_status in {"success", "warning"}:
            findings_status = "validated_no_session"
        else:
            findings_status = "execution_error"
    elif module_inspection_failed:
        findings_status = "execution_error"

    findings: Dict[str, Any] = {
        "search_terms": dedupe_terms(search_terms),
        "matched_terms": dedupe_terms(matched_terms),
        "status": findings_status,
        "session_opened": session_opened,
        "verified_session_ids": sorted(str(key) for key in verified_sessions),
    }
    if matched_skill_names:
        findings["matched_skills"] = dedupe_terms(matched_skill_names)
    if candidate_modules:
        findings["candidate_modules"] = dedupe_terms(candidate_modules)
    if selected_module:
        findings["selected_module"] = selected_module
        findings["module"] = selected_module
    if module_inspection_failed:
        findings["module_inspection_failed"] = True
        findings["module_inspection_error"] = module_inspection_error
    if last_execution:
        findings.update(last_execution)
        findings["status"] = findings_status
        if selected_module:
            findings["selected_module"] = selected_module
            findings["module"] = selected_module
        elif last_execution.get("executed_module") is None:
            findings.pop("module", None)
    elif saw_tool_activity:
        findings.update(
            {
                "module": selected_module or None,
                "selected_module": selected_module or None,
                "stop_reason": stop_reason or "No acceptable Metasploit module matched current evidence.",
            }
        )
    if last_execution and stop_reason:
        findings["stop_reason"] = stop_reason

    updates: Dict[str, Any] = {**base_update, **log_action_payload}
    updates["agent_log"][0].reasoning = reasoning or context
    updates["agent_log"][0].target = last_execution.get("target", default_target)
    updates["agent_log"][0].findings = findings or None

    if last_execution:
        # Persist the concrete attempt so supervisor and future striker runs can reason over it.
        updates["exploited_services"] = [*state.get("exploited_services", []), last_execution]
        updates["exploit_attempts"] = [
            {
                "target": last_execution.get("target", default_target),
                "module": last_execution.get("module", "unknown"),
                "status": findings_status,
                "session_id": last_execution.get("session_id"),
                "summary": stop_reason or reasoning[:240] or "striker execution",
            }
        ]
    if session_opened and session_id is not None:
        target = last_execution.get("target", default_target)
        updates["active_sessions"] = {
            **state.get("active_sessions", {}),
            target: {
                "session_id": session_id,
                "module": last_execution.get("executed_module") or last_execution.get("module", "unknown"),
                "established_at": datetime.now().isoformat(),
            },
        }
        updates["critical_findings"] = [f"Session {session_id} opened on {target} via {last_execution.get('executed_module') or last_execution.get('module', 'unknown')}"]
    elif findings_status == "validated_no_session" and last_execution:
        updates["critical_findings"] = [
            f"Striker validated a fallback path on {last_execution.get('target', default_target)} via {last_execution.get('executed_tool', last_execution.get('module', 'unknown'))} without opening a session"
        ]
    if collected_artifacts:
        updates["artifacts"] = collected_artifacts
    return updates

