# pytest tests/db_tests/test_session_persistence.py

import pytest
from psycopg2 import OperationalError
from dotenv import load_dotenv
load_dotenv()

from src.database.manager import (
    close_session,
    test_connection,
    get_sessions_by_mission,
    sync_sessions_for_mission,
    upsert_session,
)


@pytest.fixture(autouse=True)
def require_database():
    try:
        test_connection()
    except OperationalError as exc:
        pytest.skip(f"Database unavailable for session persistence test: {exc}")


def test_upsert_and_close_session():
    mission_id = "mission-session-001"

    created = upsert_session(
        mission_id=mission_id,
        session_id=101,
        target_ip="10.10.10.10",
        target_port=22,
        user_context="root",
        session_type="meterpreter",
        exploit_used="exploit/linux/ssh/test",
    )
    assert created["session_id"] == 101

    updated = upsert_session(
        mission_id=mission_id,
        session_id=101,
        target_ip="10.10.10.10",
        user_context="www-data",
        notes="post-exploitation updated",
    )
    assert updated["user_context"] == "www-data"

    closed = close_session(mission_id, 101, notes="completed")
    assert closed["closed_at"] is not None


def test_sync_sessions_closes_missing_records():
    mission_id = "mission-session-002"

    upsert_session(
        mission_id=mission_id,
        session_id=201,
        target_ip="10.10.20.20",
        session_type="shell",
    )
    upsert_session(
        mission_id=mission_id,
        session_id=202,
        target_ip="10.10.20.21",
        session_type="shell",
    )

    sync_sessions_for_mission(
        mission_id=mission_id,
        active_sessions={
            "10.10.20.20": {
                "session_id": 201,
                "session_type": "shell",
                "module": "scanner/ssh/ssh_login",
            }
        },
    )

    sessions = get_sessions_by_mission(mission_id)
    by_id = {row["session_id"]: row for row in sessions}
    assert by_id[201]["closed_at"] is None
    assert by_id[202]["closed_at"] is not None
