# tests/test_database.py

from src.database.manager import test_connection, create_target, get_targets


def test_db_connection():
    row = test_connection()
    assert row["ok"] == 1


def test_create_and_read_target():
    created = create_target(
        name="Test from pytest",
        target_type="web_app",
        target_url="http://localhost:8000",
        status="active",
        description="Target created in test_create_and_read_target",
    )
    assert created["id"] is not None

    targets = get_targets()
    assert any(t["id"] == created["id"] for t in targets)
