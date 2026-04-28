from __future__ import annotations

from src.database.librarian.models import LibrarianDependencyStatus


def build_dependency_status() -> LibrarianDependencyStatus:
    status = LibrarianDependencyStatus()
    for dependency in ("kb", "findings", "cve", "osint", "llm", "embeddings"):
        status.mark(dependency, "idle")
    return status
