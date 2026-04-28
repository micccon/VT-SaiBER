from __future__ import annotations

from typing import Any, Dict, Optional

from psycopg2.extras import RealDictCursor

from src.database.connection import get_connection


def get_session_by_mission_and_session_id(mission_id: str, session_id: int):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM sessions
                WHERE mission_id = %s AND session_id = %s
                ORDER BY established_at DESC NULLS LAST, id DESC
                LIMIT 1;
                """,
                (mission_id, session_id),
            )
            return cur.fetchone()
    finally:
        conn.close()


def upsert_session(
    mission_id: str,
    session_id: int,
    target_ip: str,
    *,
    target_port: Optional[int] = None,
    user_context: Optional[str] = None,
    session_type: Optional[str] = None,
    exploit_used: Optional[str] = None,
    established_at: Optional[str] = None,
    notes: Optional[str] = None,
):
    existing = get_session_by_mission_and_session_id(mission_id, session_id)
    if existing is None:
        conn = get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO sessions (
                        mission_id, session_id, target_ip, target_port, user_context,
                        session_type, exploit_used, established_at, notes
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, COALESCE(%s, NOW()), %s)
                    RETURNING *;
                    """,
                    (
                        mission_id,
                        session_id,
                        target_ip,
                        target_port,
                        user_context,
                        session_type,
                        exploit_used,
                        established_at,
                        notes,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
            return row
        finally:
            conn.close()

    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE sessions
                SET
                    target_ip = %s,
                    target_port = COALESCE(%s, target_port),
                    user_context = COALESCE(%s, user_context),
                    session_type = COALESCE(%s, session_type),
                    exploit_used = COALESCE(%s, exploit_used),
                    established_at = COALESCE(%s, established_at),
                    closed_at = NULL,
                    notes = COALESCE(%s, notes)
                WHERE id = %s
                RETURNING *;
                """,
                (
                    target_ip,
                    target_port,
                    user_context,
                    session_type,
                    exploit_used,
                    established_at,
                    notes,
                    existing["id"],
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def get_sessions_by_mission(mission_id: str, include_closed: bool = True):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if include_closed:
                cur.execute(
                    "SELECT * FROM sessions WHERE mission_id = %s ORDER BY established_at DESC NULLS LAST, id DESC;",
                    (mission_id,),
                )
            else:
                cur.execute(
                    """
                    SELECT *
                    FROM sessions
                    WHERE mission_id = %s AND closed_at IS NULL
                    ORDER BY established_at DESC NULLS LAST, id DESC;
                    """,
                    (mission_id,),
                )
            return cur.fetchall()
    finally:
        conn.close()


def close_session(mission_id: str, session_id: int, notes: Optional[str] = None):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE sessions
                SET
                    closed_at = NOW(),
                    notes = COALESCE(%s, notes)
                WHERE mission_id = %s AND session_id = %s AND closed_at IS NULL
                RETURNING *;
                """,
                (notes, mission_id, session_id),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def sync_sessions_for_mission(
    mission_id: str,
    active_sessions: Dict[str, Dict[str, Any]],
    *,
    target_ports: Optional[Dict[str, int]] = None,
):
    target_ports = dict(target_ports or {})
    current_session_ids = set()
    for target_ip, info in (active_sessions or {}).items():
        if not isinstance(info, dict):
            continue
        session_id = info.get("session_id")
        if session_id is None:
            continue
        current_session_ids.add(int(session_id))
        notes_parts = []
        for key in ("privilege", "os_info", "post_exploitation_at"):
            value = info.get(key)
            if value:
                notes_parts.append(f"{key}={value}")
        upsert_session(
            mission_id=mission_id,
            session_id=int(session_id),
            target_ip=target_ip,
            target_port=target_ports.get(target_ip),
            user_context=info.get("user_context") or info.get("user") or info.get("privilege"),
            session_type=info.get("session_type"),
            exploit_used=info.get("module") or info.get("exploit_used"),
            established_at=info.get("established_at") or info.get("established"),
            notes="; ".join(notes_parts) or None,
        )

    open_sessions = get_sessions_by_mission(mission_id, include_closed=False)
    for session in open_sessions:
        if int(session["session_id"]) not in current_session_ids:
            close_session(mission_id, int(session["session_id"]), notes="Closed by state sync")
