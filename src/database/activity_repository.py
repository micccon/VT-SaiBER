from __future__ import annotations

import json

from psycopg2.extras import RealDictCursor

from src.database.connection import get_connection


def create_agent_log(mission_id, agent_name, action, reasoning, result_summary, details, created_at=None):
    conn = get_connection()
    try:
        json_details = json.dumps(details) if details is not None else None
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO agent_logs (mission_id, agent_name, action, reasoning, result_summary, details)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING *;
                """,
                (mission_id, agent_name, action, reasoning, result_summary, json_details),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def get_agent_logs_by_mission(mission_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM agent_logs WHERE mission_id = %s ORDER BY created_at DESC;",
                (mission_id,),
            )
            return cur.fetchall()
    finally:
        conn.close()


def agent_log_exists_by_persistence_key(mission_id: str, persistence_key: str) -> bool:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM agent_logs
                WHERE mission_id = %s
                  AND details->>'persistence_key' = %s
                LIMIT 1;
                """,
                (mission_id, persistence_key),
            )
            return cur.fetchone() is not None
    finally:
        conn.close()
