from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Dict

import psycopg2
from pgvector.psycopg2 import register_vector
from psycopg2.extras import RealDictCursor

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
REPO_ROOT = Path(__file__).resolve().parents[2]

if load_dotenv is not None:
    load_dotenv(REPO_ROOT / ".env")

PERFORMANCE_INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS targets_mission_ip_idx ON targets (mission_id, ip_address);",
    "CREATE INDEX IF NOT EXISTS services_target_port_idx ON services (target_id, port);",
    "CREATE INDEX IF NOT EXISTS findings_mission_target_created_idx ON findings (mission_id, target_ip, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS findings_mission_agent_created_idx ON findings (mission_id, agent_name, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS findings_persistence_key_idx ON findings ((data->>'persistence_key')) WHERE data ? 'persistence_key';",
    "CREATE INDEX IF NOT EXISTS agent_logs_mission_created_idx ON agent_logs (mission_id, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS agent_logs_persistence_key_idx ON agent_logs ((details->>'persistence_key')) WHERE details ? 'persistence_key';",
    "CREATE INDEX IF NOT EXISTS sessions_mission_session_idx ON sessions (mission_id, session_id);",
    "CREATE INDEX IF NOT EXISTS sessions_mission_target_open_idx ON sessions (mission_id, target_ip, closed_at, established_at DESC);",
    "CREATE INDEX IF NOT EXISTS attack_chain_mission_step_idx ON attack_chain (mission_id, step_number);",
    "CREATE INDEX IF NOT EXISTS attack_chain_mission_time_idx ON attack_chain (mission_id, timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS knowledge_base_source_path_idx ON knowledge_base ((metadata->>'source_path'));",
    "CREATE INDEX IF NOT EXISTS knowledge_base_tool_idx ON knowledge_base ((metadata->>'tool'));",
    "CREATE INDEX IF NOT EXISTS knowledge_base_metadata_gin_idx ON knowledge_base USING gin (metadata);",
)


def _get_db_settings() -> Dict[str, str]:
    return {
        "dbname": os.getenv("DB_NAME", "vtsaiber"),
        "user": os.getenv("DB_USER", "vtsaiber"),
        "password": os.getenv("DB_PASSWORD", "password"),
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
    }


def _ensure_vector_extension(conn) -> None:
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def _schema_is_initialized(conn) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('public.targets');")
        row = cur.fetchone()
    return bool(row and row[0])


def _bootstrap_schema_if_needed(conn) -> None:
    if _schema_is_initialized(conn):
        return

    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    logger.warning("Database schema missing; bootstrapping from %s", SCHEMA_PATH)
    try:
        with conn.cursor() as cur:
            cur.execute(schema_sql)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def get_connection():
    conn = psycopg2.connect(**_get_db_settings())
    _ensure_vector_extension(conn)
    _bootstrap_schema_if_needed(conn)
    register_vector(conn)
    return conn


@lru_cache(maxsize=1)
def ensure_runtime_indexes() -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            for ddl in PERFORMANCE_INDEX_DDL:
                cur.execute(ddl)
        conn.commit()
    finally:
        conn.close()


def test_connection():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT 1 AS ok;")
            return cur.fetchone()
    finally:
        conn.close()
