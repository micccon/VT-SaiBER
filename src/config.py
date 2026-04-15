"""
Runtime configuration for VT-SaiBER orchestration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _build_database_url() -> Optional[str]:
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
    openrouter_api_key: str
    openrouter_base_url: str
    supervisor_model: str
    supervisor_timeout_seconds: int
    supervisor_reasoning_enabled: bool
    supervisor_max_reasoning_messages: int
    max_iterations: int
    checkpoint_enabled: bool
    checkpoint_database_url: Optional[str]
    default_thread_prefix: str

    tavily_api_key: str | None = None
    tavily_max_results: int = 5

@lru_cache(maxsize=1)
def get_runtime_config() -> RuntimeConfig:
    return RuntimeConfig(
        openrouter_api_key=os.getenv("OPENROUTER_API_KEY", "").strip(),
        openrouter_base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").strip(),
        supervisor_model=os.getenv("SUPERVISOR_MODEL", "minimax/minimax-m2.5:free").strip(),
        supervisor_timeout_seconds=_env_int("SUPERVISOR_TIMEOUT_SECONDS", 90),
        supervisor_reasoning_enabled=_env_bool("SUPERVISOR_REASONING_ENABLED", True),
        supervisor_max_reasoning_messages=_env_int("SUPERVISOR_MAX_REASONING_MESSAGES", 12),
        max_iterations=_env_int("MAX_ITERATIONS", 20),
        checkpoint_enabled=_env_bool("CHECKPOINT_ENABLED", True),
        checkpoint_database_url=_build_database_url(),
        default_thread_prefix=os.getenv("THREAD_ID_PREFIX", "mission").strip() or "mission",
        tavily_api_key=(os.getenv("TAVILY_API_KEY") or "").strip() or None,
        tavily_max_results=_env_int("TAVILY_MAX_RESULTS", 5),
    )

