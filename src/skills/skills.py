"""Minimal markdown skill loader for agents."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path


SKILLS_ROOT = Path(__file__).resolve().parent


def _strip_frontmatter(raw_text: str) -> str:
    if not raw_text.startswith("---\n"):
        return raw_text.strip()

    parts = raw_text.split("\n---\n", 1)
    if len(parts) != 2:
        return raw_text.strip()
    return parts[1].strip()


@lru_cache(maxsize=None)
def _load_skill_text(relative_path: str) -> str:
    return _strip_frontmatter((SKILLS_ROOT / relative_path).read_text(encoding="utf-8"))


class Skill:
    def __init__(self, relative_path: str):
        self.relative_path = relative_path

    def render(self) -> str:
        return _load_skill_text(self.relative_path)


def build_skills(paths: list[str]) -> list[Skill]:
    return [Skill(path) for path in paths]
