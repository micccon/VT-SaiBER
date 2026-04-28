from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from src.state.cyber_state import CyberState


SKILL_METADATA_RE = re.compile(r"^applies to:\s*(.+)$", re.IGNORECASE)
SKILLS_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class SkillDoc:
    """Parsed markdown skill with lightweight keyword metadata."""

    name: str
    relative_path: str
    applies_to: Tuple[str, ...]
    body: str


@dataclass(frozen=True)
class SkillMatch:
    """Scored skill match for the current mission state."""

    skill: SkillDoc
    score: int
    matched_terms: Tuple[str, ...]


def _normalize_term(value: str) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _dedupe_terms(values: Iterable[str]) -> Tuple[str, ...]:
    seen = set()
    deduped: List[str] = []
    for value in values:
        normalized = _normalize_term(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return tuple(deduped)


def _discover_skill_files() -> List[Path]:
    return sorted(path for path in SKILLS_ROOT.rglob("*.md") if path.is_file())


def _parse_skill_file(path: Path) -> SkillDoc | None:
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    metadata_index = -1
    metadata_line = ""
    for index, line in enumerate(lines):
        if line.strip():
            metadata_index = index
            metadata_line = line.strip()
            break
    if metadata_index < 0:
        return None
    match = SKILL_METADATA_RE.match(metadata_line)
    if match is None:
        return None
    applies_to = _dedupe_terms(match.group(1).split(","))
    body = "\n".join(lines[metadata_index + 1:]).strip()
    if not applies_to or not body:
        return None
    return SkillDoc(
        name=path.stem,
        relative_path=path.relative_to(SKILLS_ROOT).as_posix(),
        applies_to=applies_to,
        body=body,
    )


@lru_cache(maxsize=1)
def _load_skill_catalog() -> Tuple[SkillDoc, ...]:
    skills: List[SkillDoc] = []
    for path in _discover_skill_files():
        parsed = _parse_skill_file(path)
        if parsed is not None:
            skills.append(parsed)
    return tuple(skills)


def _stringify_collection(values: Iterable[Any], *, limit: int | None = None) -> str:
    items: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text:
            items.append(text)
        if limit is not None and len(items) >= limit:
            break
    return "\n".join(items)


def _summarize_targets(state: CyberState) -> str:
    lines: List[str] = []
    for target, data in (state.get("discovered_targets", {}) or {}).items():
        if not isinstance(data, dict):
            lines.append(str(target))
            continue
        lines.append(f"target={target}")
        if data.get("ip_address"):
            lines.append(f"ip={data.get('ip_address')}")
        if data.get("os_guess"):
            lines.append(f"os={data.get('os_guess')}")
        services = data.get("services", {}) or {}
        for port, service in list(services.items())[:12]:
            if isinstance(service, dict):
                lines.append(
                    "service={port} {name} {version} {banner}".format(
                        port=port,
                        name=service.get("service_name", ""),
                        version=service.get("version", ""),
                        banner=service.get("banner", ""),
                    ).strip()
                )
            else:
                lines.append(f"service={port} {service}")
    return _stringify_collection(lines)


def _summarize_web_findings(state: CyberState) -> str:
    lines: List[str] = []
    for finding in (state.get("web_findings", []) or [])[:12]:
        if isinstance(finding, dict):
            lines.append(
                json.dumps(
                    {
                        "url": finding.get("url"),
                        "path": finding.get("path"),
                        "status_code": finding.get("status_code"),
                        "title": finding.get("title"),
                        "is_interesting": finding.get("is_interesting"),
                    },
                    default=str,
                )
            )
        else:
            lines.append(str(finding))
    return _stringify_collection(lines)


def _summarize_research(state: CyberState) -> str:
    lines: List[str] = []
    for key, value in list((state.get("research_cache", {}) or {}).items())[:8]:
        lines.append(f"{key}: {value}")
    for finding in (state.get("intelligence_findings", []) or [])[:8]:
        lines.append(json.dumps(finding, default=str) if isinstance(finding, dict) else str(finding))
    return _stringify_collection(lines)


def _summarize_attempts(state: CyberState) -> str:
    lines: List[str] = []
    for attempt in (state.get("exploit_attempts", []) or [])[-8:]:
        lines.append(json.dumps(attempt, default=str) if isinstance(attempt, dict) else str(attempt))
    for attempt in (state.get("exploited_services", []) or [])[-8:]:
        lines.append(json.dumps(attempt, default=str) if isinstance(attempt, dict) else str(attempt))
    return _stringify_collection(lines)


def _summarize_protocols(state: CyberState) -> str:
    lines: List[str] = []
    for collection_name in ("protocol_observations", "fuzzing_runs", "crash_indicators", "artifacts"):
        for item in (state.get(collection_name, []) or [])[-8:]:
            lines.append(json.dumps(item, default=str) if isinstance(item, dict) else str(item))
    return _stringify_collection(lines)


def _build_match_sections(state: CyberState) -> List[Tuple[str, int]]:
    expectations = state.get("supervisor_expectations", {}) or {}
    return [
        (str(state.get("mission_goal", "") or ""), 4),
        (str(expectations.get("specific_goal", "") or ""), 5),
        (_summarize_targets(state), 3),
        (_summarize_web_findings(state), 2),
        (_summarize_research(state), 2),
        (_summarize_attempts(state), 2),
        (_summarize_protocols(state), 2),
    ]


def match_skills(state: CyberState, agent_name: str, limit: int = 2) -> List[SkillMatch]:
    """Return the top matching markdown skills for the given mission state."""

    _ = agent_name
    sections = [(_normalize_term(text), weight) for text, weight in _build_match_sections(state) if str(text or "").strip()]
    matches: List[SkillMatch] = []
    for skill in _load_skill_catalog():
        matched_terms: List[str] = []
        score = 0
        for term in skill.applies_to:
            term_hits = 0
            for text, weight in sections:
                if term and term in text:
                    term_hits += text.count(term) * weight
            if term_hits:
                matched_terms.append(term)
                score += term_hits
        if score > 0:
            matches.append(
                SkillMatch(
                    skill=skill,
                    score=score,
                    matched_terms=tuple(matched_terms),
                )
            )
    matches.sort(key=lambda item: (-item.score, item.skill.relative_path))
    return matches[: max(0, limit)]


def render_skill_matches(matches: Iterable[SkillMatch]) -> str:
    """Render matched skills into a compact prompt-friendly section."""

    rendered: List[str] = []
    for match in matches:
        rendered.append(
            "SKILL: {name}\nMATCHED TERMS: {terms}\n{body}".format(
                name=match.skill.relative_path,
                terms=", ".join(match.matched_terms) or "none",
                body=match.skill.body.strip(),
            ).strip()
        )
    return "\n\n".join(rendered)
