"""Mission context building for Striker v2."""

from __future__ import annotations

import json
from typing import Any

from src.state.cyber_state import CyberState
from src.v2.agents.striker.constants import METASPLOIT_DEFAULT_SERVICES


def dedupe_terms(values: list[str]) -> list[str]:
    """Preserve order while removing empty or duplicate string values."""

    seen = set()
    deduped: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return deduped


def parse_services(target_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize discovered services into a predictable list."""

    services = target_data.get("services", {}) or {}
    parsed: list[dict[str, Any]] = []
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


def _format_targets(state: CyberState) -> str:
    lines: list[str] = []
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


def _format_web_findings(state: CyberState) -> str:
    lines: list[str] = []
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


def _format_raw_run_evidence(state: CyberState, key: str, title: str, *, max_chars: int = 6000) -> str:
    """Format captured tool-run evidence such as Nmap, Gobuster, and Nikto output."""

    lines: list[str] = []
    for run in (state.get(key, []) or [])[:6]:
        if not isinstance(run, dict):
            continue
        tool = str(run.get("tool") or "unknown")
        target = str(run.get("target") or "unknown")
        status = str(run.get("status") or "unknown")
        summary = str(run.get("summary") or "").strip()
        raw = str(run.get("raw_stdout") or run.get("stdout") or "").strip()
        lines.append(f"- {title}: tool={tool} target={target} status={status}")
        if summary:
            lines.append(f"  summary: {summary}")
        if raw:
            snippet = raw[:max_chars]
            suffix = "\n  ...(truncated)" if len(raw) > max_chars else ""
            lines.append(f"  raw:\n{snippet}{suffix}")
    return "\n".join(lines) if lines else "- none"


def _format_research_hints(state: CyberState) -> str:
    hints: list[str] = []
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


def _format_prior_attempts(state: CyberState) -> str:
    attempts: list[str] = []
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
    research_cache: dict[str, Any],
    intelligence_findings: list[dict[str, Any]],
    service_name: str,
    version: str,
) -> dict[str, Any]:
    indicators = {"metasploit", "msf", "exploit/"}
    has_research = has_version_research = has_intelligence = has_version_intelligence = suggests_metasploit = False
    cves: list[str] = []
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


def _attempt_matches_service(service_name: str, attempt: dict[str, Any]) -> bool:
    module = str(attempt.get("module", "")).lower()
    if service_name.startswith("http"):
        return any(token in module for token in {"http", "apache", "tomcat", "nginx", "web"})
    if service_name == "smb":
        return "smb" in module or "samba" in module
    return service_name in module


def rank_candidates(state: CyberState) -> list[dict[str, Any]]:
    """Rank a small set of candidate exploitation paths from current evidence."""

    discovered_targets = state.get("discovered_targets", {}) or {}
    research_cache = state.get("research_cache", {}) or {}
    intelligence_findings = state.get("intelligence_findings", []) or []
    web_findings = state.get("web_findings", []) or []
    prior_attempts = state.get("exploited_services", []) or []
    candidates: list[dict[str, Any]] = []

    for target, target_data in discovered_targets.items():
        for service in parse_services(target_data):
            intel = _collect_service_intel(
                research_cache,
                intelligence_findings,
                service["name"],
                service["version"].lower(),
            )
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
            if service["name"].startswith("http") and any(
                isinstance(item, dict) and (item.get("is_interesting") or item.get("status_code") in {200, 301, 302, 403})
                for item in web_findings
            ):
                score += 2
                reasons.append("interesting web findings present")
            if any(
                isinstance(item, dict)
                and item.get("target") == target
                and _attempt_matches_service(service["name"], item)
                and str(item.get("status", "")).lower() not in {"success", "opened", "succeeded"}
                for item in prior_attempts
            ):
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


def _format_candidates(candidates: list[dict[str, Any]]) -> str:
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


def build_striker_context(state: CyberState) -> str:
    """Build the full exploitation context block shown to Striker v2."""

    return (
        f"MISSION: {state.get('mission_goal') or '(not specified)'}\n\n"
        f"TARGET INTELLIGENCE:\n{_format_targets(state)}\n\n"
        f"SCOUT / NMAP EVIDENCE:\n{_format_raw_run_evidence(state, 'reconnaissance_runs', 'scout')}\n\n"
        f"RELEVANT WEB FINDINGS:\n{_format_web_findings(state)}\n\n"
        f"FUZZER RAW SCAN EVIDENCE:\n{_format_raw_run_evidence(state, 'fuzzing_runs', 'fuzzer')}\n\n"
        f"RESEARCH / INTELLIGENCE HINTS:\n{_format_research_hints(state)}\n\n"
        f"PRIOR EXPLOIT ATTEMPTS:\n{_format_prior_attempts(state)}\n\n"
        f"CANDIDATE PATHS:\n{_format_candidates(rank_candidates(state))}\n"
    )
