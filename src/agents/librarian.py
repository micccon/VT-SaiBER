"""
Librarian Agent - research and intelligence worker.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from src.agents.base import BaseAgent
from src.config import get_runtime_config
from src.state.cyber_state import CyberState
from src.state.models import IntelligenceBrief
from src.utils.openrouter_client import OpenRouterClient, OpenRouterError
from src.utils.parsers import extract_json_payload


class LibrarianAgent(BaseAgent):
    """Produces structured research briefs with citations and confidence."""

    def __init__(self):
        super().__init__("librarian", "Research and Intelligence Specialist")
        cfg = get_runtime_config()
        self._client = None
        if cfg.openrouter_api_key:
            self._client = OpenRouterClient(
                api_key=cfg.openrouter_api_key,
                model=cfg.supervisor_model,
                base_url=cfg.openrouter_base_url,
                timeout_seconds=cfg.supervisor_timeout_seconds,
            )

    @property
    def system_prompt(self) -> str:
        return """You are a cybersecurity research specialist.
Return one JSON object with:
- summary (string)
- technical_params (object string:string)
- is_osint_derived (boolean)
- confidence (0..1 float)
- citations (array of URLs or source identifiers)
- conflicting_sources (array of strings or null)
Do not execute tools, only provide cited intelligence."""

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        query = self._build_research_query(state)
        brief = await self._research_brief(query)

        cache_key = self._cache_key(query)
        research_cache = dict(state.get("research_cache", {}) or {})
        research_cache[cache_key] = brief.model_dump()

        osint_findings = [{
            "source": "librarian",
            "description": brief.summary,
            "exploit_available": bool(brief.technical_params.get("exploit_module")),
            "data": {
                "technical_params": brief.technical_params,
                "citations": brief.citations,
                "confidence": brief.confidence,
                "conflicting_sources": brief.conflicting_sources or [],
            },
        }]

        return {
            "current_agent": "librarian",
            "research_cache": research_cache,
            "osint_findings": osint_findings,
            **self.log_action(
                state,
                action="research_brief",
                findings={
                    "query": query,
                    "citations": brief.citations,
                    "confidence": brief.confidence,
                },
                reasoning="Librarian produced cited intelligence brief",
            ),
        }

    def _build_research_query(self, state: CyberState) -> str:
        segments: List[str] = [f"mission={state.get('mission_goal', '')}"]
        discovered_targets = state.get("discovered_targets", {}) or {}
        web_findings = state.get("web_findings", []) or []

        for ip, target_data in list(discovered_targets.items())[:2]:
            services = target_data.get("services", {}) if isinstance(target_data, dict) else {}
            service_bits = []
            for port, service in list(services.items())[:6]:
                if isinstance(service, dict):
                    service_name = service.get("service_name", "unknown")
                    version = service.get("version", "")
                    if version:
                        service_bits.append(f"{port}/{service_name} {version}")
                    else:
                        service_bits.append(f"{port}/{service_name}")
                else:
                    service_bits.append(f"{port}/{service}")
            if service_bits:
                segments.append(f"target={ip} services={'; '.join(service_bits)}")

        interesting_paths = []
        for finding in web_findings[:10]:
            if not isinstance(finding, dict):
                continue
            path = finding.get("path") or finding.get("url")
            status = finding.get("status_code", finding.get("status"))
            if path:
                interesting_paths.append(f"{path} ({status})")
        if interesting_paths:
            segments.append(f"web_findings={', '.join(interesting_paths)}")

        # Prompt-injection hygiene: keep the query as plain compact telemetry.
        return " | ".join(segments).replace("\n", " ").replace("`", "").strip()

    async def _research_brief(self, query: str) -> IntelligenceBrief:
        if self._client is None:
            return IntelligenceBrief(
                summary=f"Fallback intelligence brief for: {query}",
                technical_params={},
                is_osint_derived=False,
                confidence=0.3,
                citations=[],
                conflicting_sources=None,
            )

        try:
            response = await self._client.chat_completion(
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": query},
                ],
                temperature=0.0,
                reasoning_enabled=True,
            )
            payload = extract_json_payload(response.content)
            if "confidence_score" in payload and "confidence" not in payload:
                payload["confidence"] = payload["confidence_score"]
            return IntelligenceBrief.model_validate(payload)
        except (OpenRouterError, ValueError):
            return IntelligenceBrief(
                summary=f"Research unavailable; captured fallback for query: {query}",
                technical_params={},
                is_osint_derived=False,
                confidence=0.2,
                citations=[],
                conflicting_sources=None,
            )

    def _cache_key(self, query: str) -> str:
        digest = hashlib.sha1(query.encode("utf-8")).hexdigest()[:10]
        return f"research_{digest}"


async def librarian_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper."""
    agent = LibrarianAgent()
    return await agent.call_llm(state)
