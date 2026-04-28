from __future__ import annotations

from typing import Any, Dict, List
from src.state.cyber_state import CyberState


class TelemetryProcessor:
    """
    responsible for converting raw telemetry data 
    into a compact string format suitable for LLM input
    """

    @staticmethod
    def build_research_inputs(state: CyberState) -> Dict[str, Any]:
        """Collect the CyberState fields that make a librarian query actionable."""

        discovered_targets = state.get("discovered_targets", {}) or {}
        web_findings = state.get("web_findings", []) or []
        agent_log = state.get("agent_log", []) or []
        intelligence_findings = state.get("intelligence_findings", []) or []
        research_cache = state.get("research_cache", {}) or {}
        active_sessions = state.get("active_sessions", {}) or {}

        services: List[Dict[str, Any]] = []
        for ip, target_data in list(discovered_targets.items())[:3]:
            # Keep the query compact while preserving target/service/version/banners.
            service_map = target_data.get("services", {}) if isinstance(target_data, dict) else {}
            for port, service in list((service_map or {}).items())[:10]:
                if isinstance(service, dict):
                    services.append(
                        {
                            "target": ip,
                            "port": str(port),
                            "service_name": service.get("service_name", "unknown"),
                            "version": service.get("version") or service.get("service_version"),
                            "banner": service.get("banner"),
                        }
                    )
                else:
                    services.append(
                        {
                            "target": ip,
                            "port": str(port),
                            "service_name": str(service or "unknown"),
                            "version": None,
                            "banner": None,
                        }
                    )

        recent_attempts: List[Dict[str, Any]] = []
        # Exploit failures and striker logs help librarian research alternate paths.
        for item in (state.get("exploit_attempts", []) or [])[-5:]:
            if isinstance(item, dict):
                recent_attempts.append(dict(item))
        for entry in agent_log[-6:]:
            if isinstance(entry, dict) and str(entry.get("agent") or "").strip().lower() == "striker":
                recent_attempts.append(
                    {
                        "action": entry.get("action"),
                        "decision": entry.get("decision"),
                        "reasoning": entry.get("reasoning"),
                        "findings": entry.get("findings"),
                    }
                )

        protocol_observations: List[Dict[str, Any]] = []
        for item in (state.get("protocol_observations", []) or [])[-6:]:
            if isinstance(item, dict):
                protocol_observations.append(dict(item))

        cve_candidates: List[str] = []
        # Reuse prior CVE hints so retries can go straight to official evidence.
        for finding in intelligence_findings[-8:]:
            if not isinstance(finding, dict):
                continue
            technical_params = finding.get("technical_params", {}) or {}
            for candidate in (technical_params.get("cve"), finding.get("cve")):
                if isinstance(candidate, str) and candidate.strip() and candidate not in cve_candidates:
                    cve_candidates.append(candidate.strip())
        for cached in list(research_cache.values())[-8:]:
            if not isinstance(cached, dict):
                continue
            technical_params = cached.get("technical_params", {}) or {}
            candidate = technical_params.get("cve")
            if isinstance(candidate, str) and candidate.strip() and candidate not in cve_candidates:
                cve_candidates.append(candidate.strip())

        session_summaries: List[Dict[str, Any]] = []
        if isinstance(active_sessions, dict):
            for target, info in list(active_sessions.items())[:4]:
                if isinstance(info, dict):
                    session_summaries.append({"target": target, **info})

        return {
            "mission_goal": state.get("mission_goal", ""),
            "specific_goal": (state.get("supervisor_expectations", {}) or {}).get("specific_goal", ""),
            "services": services,
            "web_findings": [item for item in web_findings[:10] if isinstance(item, dict)],
            "protocol_observations": protocol_observations,
            "recent_attempts": recent_attempts[-6:],
            "active_sessions": session_summaries,
            "cve_candidates": cve_candidates[:6],
        }

    @staticmethod
    def build_research_query(state: CyberState) -> str:
        """Render normalized inputs into a compact single-line retrieval query."""

        inputs = TelemetryProcessor.build_research_inputs(state)
        segments: List[str] = [f"mission={inputs.get('mission_goal', '')}"]

        specific_goal = str(inputs.get("specific_goal") or "").strip()
        if specific_goal:
            segments.append(f"goal={specific_goal}")

        for service in inputs.get("services", [])[:10]:
            # Service/version/banner terms drive both KB retrieval and CVE matching.
            target = service.get("target", "unknown")
            name = service.get("service_name", "unknown")
            port = service.get("port", "?")
            version = str(service.get("version") or "").strip()
            banner = str(service.get("banner") or "").strip()
            piece = f"target={target} service={port}/{name}"
            if version:
                piece += f" version={version}"
            if banner:
                piece += f" banner={banner[:80]}"
            segments.append(piece)

        interesting_paths: List[str] = []
        for finding in inputs.get("web_findings", [])[:8]:
            path = finding.get("path") or finding.get("url")
            status = finding.get("status_code", finding.get("status"))
            if path:
                interesting_paths.append(f"{path} ({status})" if status is not None else str(path))
        if interesting_paths:
            segments.append(f"web_findings={', '.join(interesting_paths)}")

        protocol_bits: List[str] = []
        for item in inputs.get("protocol_observations", [])[:5]:
            summary = str(item.get("summary") or item.get("description") or item.get("protocol") or "").strip()
            if summary:
                protocol_bits.append(summary[:100])
        if protocol_bits:
            segments.append(f"protocols={'; '.join(protocol_bits)}")

        attempt_bits: List[str] = []
        for item in inputs.get("recent_attempts", [])[:5]:
            summary = str(item.get("summary") or item.get("status") or item.get("action") or item.get("decision") or "").strip()
            if summary:
                attempt_bits.append(summary[:100])
        if attempt_bits:
            segments.append(f"recent_attempts={'; '.join(attempt_bits)}")

        session_bits: List[str] = []
        for item in inputs.get("active_sessions", [])[:4]:
            target = str(item.get("target") or "").strip()
            session_id = item.get("session_id")
            user = str(item.get("user_context") or item.get("user") or item.get("privilege") or "").strip()
            if target:
                piece = f"{target} session={session_id}"
                if user:
                    piece += f" user={user}"
                session_bits.append(piece)
        if session_bits:
            segments.append(f"active_sessions={'; '.join(session_bits)}")

        cves = inputs.get("cve_candidates", [])[:6]
        if cves:
            segments.append(f"known_cves={', '.join(str(item) for item in cves)}")

        return " | ".join(segments).replace("\n", " ").replace("`", "").strip()
