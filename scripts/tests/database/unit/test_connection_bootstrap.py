from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.database import connection


@pytest.fixture(scope="session", autouse=True)
def _db_ready() -> None:
    connection.ensure_database_ready.cache_clear()
    yield
    connection.ensure_database_ready.cache_clear()


def test_get_connection_does_not_bootstrap_schema(monkeypatch) -> None:
    connection.ensure_database_ready.cache_clear()

    fake_conn = MagicMock(name="conn")
    connect_calls = []
    register_calls = []
    vector_calls = []
    bootstrap_calls = []
    apply_calls = []

    def fake_connect(**kwargs):
        connect_calls.append(kwargs)
        return fake_conn

    monkeypatch.setattr(connection.psycopg2, "connect", fake_connect)
    monkeypatch.setattr(connection, "register_vector", lambda conn: register_calls.append(conn))
    monkeypatch.setattr(connection, "_ensure_vector_extension", lambda conn: vector_calls.append(conn))
    monkeypatch.setattr(connection, "_bootstrap_schema_if_needed", lambda conn: bootstrap_calls.append(conn))
    monkeypatch.setattr(connection, "_apply_sql_script", lambda conn, path: apply_calls.append((conn, path)))

    conn = connection.get_connection()

    assert conn is fake_conn
    assert connect_calls
    assert register_calls == [fake_conn]
    assert vector_calls == []
    assert bootstrap_calls == []
    assert apply_calls == []


def test_ensure_database_ready_is_idempotent(monkeypatch) -> None:
    connection.ensure_database_ready.cache_clear()

    fake_conn = MagicMock(name="conn")
    register_calls = []
    vector_calls = []
    bootstrap_calls = []
    apply_calls = []

    monkeypatch.setattr(connection, "get_connection", lambda: fake_conn)
    monkeypatch.setattr(connection, "register_vector", lambda conn: register_calls.append(conn))
    monkeypatch.setattr(connection, "_ensure_vector_extension", lambda conn: vector_calls.append(conn))
    monkeypatch.setattr(connection, "_bootstrap_schema_if_needed", lambda conn: bootstrap_calls.append(conn))
    monkeypatch.setattr(connection, "_apply_sql_script", lambda conn, path: apply_calls.append((conn, path)))

    connection.ensure_database_ready()
    connection.ensure_database_ready()

    assert register_calls == []
    assert vector_calls == [fake_conn]
    assert bootstrap_calls == [fake_conn]
    assert apply_calls == [(fake_conn, connection.INDEXES_PATH)]
    fake_conn.close.assert_called_once()
