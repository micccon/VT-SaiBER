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
INDEXES_PATH = Path(__file__).with_name("indexes.sql")
REPO_ROOT = Path(__file__).resolve().parents[2]

if load_dotenv is not None:
    load_dotenv(REPO_ROOT / ".env")

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


def _apply_sql_script(conn, path: Path) -> None:
    sql = path.read_text(encoding="utf-8")
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
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

    logger.warning("Database schema missing; bootstrapping from %s", SCHEMA_PATH)
    _apply_sql_script(conn, SCHEMA_PATH)


def get_connection():
    conn = psycopg2.connect(**_get_db_settings())
    register_vector(conn)
    return conn


@lru_cache(maxsize=1)
def ensure_database_ready() -> None:
    conn = get_connection()
    try:
        _ensure_vector_extension(conn)
        _bootstrap_schema_if_needed(conn)
        _apply_sql_script(conn, INDEXES_PATH)
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
