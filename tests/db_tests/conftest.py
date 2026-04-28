from __future__ import annotations

import os
import socket
import uuid
from pathlib import Path

import pytest

from src.config import get_runtime_config
from src.database.connection import ensure_runtime_indexes, get_connection


def _resolve_test_db_host() -> None:
    configured_host = (os.getenv("DB_HOST") or "").strip()
    if not configured_host:
        return

    try:
        socket.gethostbyname(configured_host)
        return
    except OSError:
        pass

    if configured_host.lower() == "postgres":
        os.environ["DB_HOST"] = "localhost"


@pytest.fixture(scope="session", autouse=True)
def _db_ready() -> None:
    _resolve_test_db_host()
    ensure_runtime_indexes()


@pytest.fixture(autouse=True)
def _clear_runtime_config_cache():
    get_runtime_config.cache_clear()
    try:
        yield
    finally:
        get_runtime_config.cache_clear()


def _cleanup_mission(mission_id: str) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM attack_chain WHERE mission_id = %s;", (mission_id,))
            cur.execute("DELETE FROM agent_logs WHERE mission_id = %s;", (mission_id,))
            cur.execute("DELETE FROM sessions WHERE mission_id = %s;", (mission_id,))
            cur.execute("DELETE FROM findings WHERE mission_id = %s;", (mission_id,))
            cur.execute(
                """
                DELETE FROM services
                WHERE target_id IN (
                    SELECT id FROM targets WHERE mission_id = %s
                );
                """,
                (mission_id,),
            )
            cur.execute("DELETE FROM targets WHERE mission_id = %s;", (mission_id,))
        conn.commit()
    finally:
        conn.close()


def _cleanup_kb_prefix(source_prefix: str) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM knowledge_base
                WHERE metadata->>'source_path' LIKE %s;
                """,
                (f"{source_prefix}%",),
            )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def mission_id() -> str:
    mission_id = f"pytest-db-{uuid.uuid4().hex[:10]}"
    _cleanup_mission(mission_id)
    try:
        yield mission_id
    finally:
        _cleanup_mission(mission_id)


@pytest.fixture
def kb_source_prefix() -> str:
    source_prefix = f"pytest://{uuid.uuid4().hex[:10]}/"
    _cleanup_kb_prefix(source_prefix)
    try:
        yield source_prefix
    finally:
        _cleanup_kb_prefix(source_prefix)


@pytest.fixture
def report_output_dir() -> Path:
    base_dir = Path("tests/.tmp_reports").resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    output_dir = base_dir / f"report-{uuid.uuid4().hex[:10]}"
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        yield output_dir
    finally:
        for child in sorted(output_dir.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink(missing_ok=True)
            elif child.is_dir():
                child.rmdir()
        output_dir.rmdir()
