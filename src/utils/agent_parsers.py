"""
Shared parsing helpers for agent tool results and target metadata.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List

from src.state.models import ServiceInfo


def extract_tool_output_text(raw_output: Any) -> str:
    payload = raw_output
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            payload = {"output": raw_output}

    if isinstance(payload, dict):
        for key in ("output", "stdout", "result", "data", "module_output"):
            value = payload.get(key)
            if isinstance(value, str):
                return value
            if isinstance(value, dict):
                nested = value.get("output") or value.get("stdout")
                if isinstance(nested, str):
                    return nested
        raw = payload.get("raw")
        if isinstance(raw, dict):
            nested = raw.get("stdout") or raw.get("output")
            if isinstance(nested, str):
                return nested
    return ""


def parse_service_records(services: List[Dict[str, Any]]) -> Dict[int, ServiceInfo]:
    parsed: Dict[int, ServiceInfo] = {}
    for service in services:
        if not isinstance(service, dict):
            continue
        port = int(service.get("port", 0) or 0)
        if port <= 0:
            continue
        parsed[port] = ServiceInfo(
            port=port,
            protocol=str(service.get("protocol", "tcp") or "tcp"),
            service_name=str(service.get("service_name", "unknown") or "unknown"),
            version=service.get("version"),
            banner=service.get("banner"),
        )
    return parsed


def parse_host_discovery_output(raw_output: Any, *, max_hosts: int = 5) -> List[str]:
    text = extract_tool_output_text(raw_output)
    if not text:
        return []

    hosts: List[str] = []
    report_regex = re.compile(r"^Nmap scan report for (.+)$", re.IGNORECASE)
    ip_regex = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    for line in text.splitlines():
        match = report_regex.match(line.strip())
        if not match:
            continue
        candidate = match.group(1).strip()
        ip_match = ip_regex.search(candidate)
        host = ip_match.group(0) if ip_match else candidate
        if host and host not in hosts:
            hosts.append(host)
    return hosts[:max_hosts]


def parse_nmap_output(raw_output: Any) -> Dict[int, ServiceInfo]:
    text = extract_tool_output_text(raw_output)
    services: Dict[int, ServiceInfo] = {}
    if not text:
        return services

    pattern = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)\s*(.*)$", re.IGNORECASE)
    for line in text.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        port = int(match.group(1))
        services[port] = ServiceInfo(
            port=port,
            protocol=match.group(2).lower(),
            service_name=match.group(3).lower(),
            version=match.group(4).strip() or None,
            banner=None,
        )
    return services


def iter_target_services(discovered_targets: Dict[str, Dict[str, Any]]) -> Iterable[tuple[str, int, str]]:
    for ip, target_data in discovered_targets.items():
        if not isinstance(target_data, dict):
            continue
        services = target_data.get("services", {}) or {}
        for port in target_data.get("ports", []) or []:
            service = services.get(str(port)) or services.get(port)
            if isinstance(service, dict):
                name = str(service.get("service_name", "")).lower()
            else:
                name = str(service or "").lower()
            yield ip, int(port), name


def parse_gobuster_output(
    raw_output: Any,
    *,
    base_url: str,
    max_depth: int,
    soft_404_statuses: set[int],
    scan_policy: Dict[str, Any],
) -> List[Dict[str, Any]]:
    text = extract_tool_output_text(raw_output)
    findings: List[Dict[str, Any]] = []
    line_regex = re.compile(r"^(/[^ ]*)\s+\(Status:\s*(\d{3})\)", re.IGNORECASE)
    for line in text.splitlines():
        match = line_regex.match(line.strip())
        if not match:
            continue
        path = match.group(1)
        status_code = int(match.group(2))
        depth = len([segment for segment in path.split("/") if segment])
        if depth > max_depth or status_code in soft_404_statuses:
            continue
        is_interesting = (
            path.startswith("/api")
            or any(token in path.lower() for token in ("admin", "login", "dashboard", "config"))
            or status_code in {200, 401, 403}
        )
        findings.append(
            {
                "url": f"{base_url}{path}",
                "path": path,
                "status_code": status_code,
                "content_length": None,
                "content_type": None,
                "is_api_endpoint": path.startswith("/api"),
                "is_interesting": is_interesting,
                "discovery_depth": depth,
                "scan_policy": scan_policy,
                "rationale": "Discovered by gobuster",
            }
        )
    return findings[:100]


def parse_nikto_output(
    raw_output: Any,
    *,
    base_url: str,
    max_depth: int,
    scan_policy: Dict[str, Any],
) -> List[Dict[str, Any]]:
    text = extract_tool_output_text(raw_output)
    findings: List[Dict[str, Any]] = []
    line_regex = re.compile(r"^\+\s+(/[^:\s]*).*?:\s*(.+)$")
    for line in text.splitlines():
        match = line_regex.match(line.strip())
        if not match:
            continue
        path = match.group(1)
        detail = match.group(2).strip()
        depth = len([segment for segment in path.split("/") if segment])
        if depth > max_depth:
            continue
        findings.append(
            {
                "url": f"{base_url}{path}",
                "path": path,
                "status_code": 0,
                "content_length": None,
                "content_type": "nikto-report",
                "is_api_endpoint": path.startswith("/api"),
                "is_interesting": True,
                "discovery_depth": depth,
                "scan_policy": scan_policy,
                "rationale": f"Nikto finding: {detail[:160]}",
            }
        )
    return findings[:50]


def dedupe_web_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for finding in findings:
        key = (finding.get("path"), finding.get("status_code"), finding.get("rationale"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
