"""
Runtime configuration for VT-SaiBER orchestration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None  # type: ignore[assignment]


_REPO_ROOT = Path(__file__).resolve().parents[1]
if load_dotenv is not None:
    load_dotenv(_REPO_ROOT / ".env")


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment flag with a safe default."""

    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Read an integer environment variable without raising on bad input."""

    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _build_database_url() -> Optional[str]:
    """Build DATABASE_URL directly or from DB_* parts when present."""

    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return database_url

    db_host = os.getenv("DB_HOST")
    db_port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    if not all([db_host, db_name, db_user, db_password]):
        return None

    return f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"


@dataclass(frozen=True)
class RuntimeConfig:
    """Resolved runtime configuration shared across the orchestration stack."""

    # OpenRouter/OpenAI client settings.
    openrouter_api_key: str
    openrouter_base_url: str
    openrouter_model: str
    supervisor_timeout_seconds: int
    supervisor_reasoning_enabled: bool
    supervisor_max_reasoning_messages: int

    # Graph and checkpointing controls.
    max_iterations: int
    checkpoint_enabled: bool
    checkpoint_database_url: Optional[str]
    default_thread_prefix: str
    trace_enabled: bool
    trace_include_raw: bool
    trace_max_chars: int

    # RAG tuning knobs used by librarian and persistence helpers.
    rag_kb_top_k: int
    rag_kb_fetch_k: int
    rag_findings_top_k: int
    rag_findings_fetch_k: int
    rag_kb_similarity_threshold: float
    rag_findings_similarity_threshold: float
    rag_min_docs: int
    rag_min_score: float
    rag_max_chunks_per_doc: int
    report_export_dir: str | None

    tavily_api_key: str | None = None
    tavily_max_results: int = 5
    openrouter_embedding_api_key: str = ""
    embedding_provider: str = "openrouter"
    embedding_model: str = "openai/text-embedding-3-small"
    embedding_dimensions: int = 1024
    embedding_timeout_seconds: int = 60

@lru_cache(maxsize=1)
def get_runtime_config() -> RuntimeConfig:
    """Resolve and cache the active runtime configuration for the process."""

    # OpenRouter model resolution keeps the new name first while still honoring older envs.
    return RuntimeConfig(
        # Keep model/backend configuration centralized so every agent shares the same defaults.
        openrouter_api_key=os.getenv("OPENROUTER_API_KEY", "").strip(),
        openrouter_base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").strip(),
        openrouter_model=(
            os.getenv("OPENROUTER_MODEL")
            or os.getenv("SUPERVISOR_MODEL")
            or os.getenv("LLM_MODEL")
            or "minimax/minimax-m2.5:free"
        ).strip(),
        supervisor_timeout_seconds=_env_int("SUPERVISOR_TIMEOUT_SECONDS", 90),
        supervisor_reasoning_enabled=_env_bool("SUPERVISOR_REASONING_ENABLED", True),
        supervisor_max_reasoning_messages=_env_int("SUPERVISOR_MAX_REASONING_MESSAGES", 12),
        max_iterations=_env_int("MAX_ITERATIONS", 20),
        checkpoint_enabled=_env_bool("CHECKPOINT_ENABLED", True),
        checkpoint_database_url=_build_database_url(),
        default_thread_prefix=os.getenv("THREAD_ID_PREFIX", "mission").strip() or "mission",
        trace_enabled=_env_bool("SAIBER_TRACE_ENABLED", False),
        trace_include_raw=_env_bool("SAIBER_TRACE_INCLUDE_RAW", False),
        trace_max_chars=_env_int("SAIBER_TRACE_MAX_CHARS", 2000),
        rag_kb_top_k=_env_int("RAG_KB_TOP_K", 8),
        rag_kb_fetch_k=_env_int("RAG_KB_FETCH_K", 24),
        rag_findings_top_k=_env_int("RAG_FINDINGS_TOP_K", 5),
        rag_findings_fetch_k=_env_int("RAG_FINDINGS_FETCH_K", 15),
        rag_kb_similarity_threshold=float(os.getenv("RAG_KB_SIMILARITY_THRESHOLD", "0.58")),
        rag_findings_similarity_threshold=float(os.getenv("RAG_FINDINGS_SIMILARITY_THRESHOLD", "0.45")),
        rag_min_docs=_env_int("RAG_MIN_DOCS", 3),
        rag_min_score=float(os.getenv("RAG_MIN_SCORE", "0.75")),
        rag_max_chunks_per_doc=_env_int("RAG_MAX_CHUNKS_PER_DOC", 2),
        report_export_dir=(os.getenv("REPORT_EXPORT_DIR") or "").strip() or "exports",
        tavily_api_key=(os.getenv("TAVILY_API_KEY") or "").strip() or None,
        tavily_max_results=_env_int("TAVILY_MAX_RESULTS", 5),
        openrouter_embedding_api_key=(os.getenv("OPENROUTER_EMBEDDING_API_KEY") or "").strip(),
        embedding_provider=(os.getenv("EMBEDDING_PROVIDER") or "openrouter").strip().lower() or "openrouter",
        embedding_model=(os.getenv("EMBEDDING_MODEL") or "openai/text-embedding-3-small").strip() or "openai/text-embedding-3-small",
        embedding_dimensions=_env_int("EMBEDDING_DIMENSIONS", 1024),
        embedding_timeout_seconds=_env_int("EMBEDDING_TIMEOUT_SECONDS", 60),
    )
