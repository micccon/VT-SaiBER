from __future__ import annotations

from typing import Optional

from psycopg2.extras import RealDictCursor

from src.database.connection import get_connection


def create_attack_chain_step(
    mission_id: str,
    agent_name: str,
    action: str,
    *,
    target: Optional[str] = None,
    outcome: Optional[str] = None,
    timestamp: Optional[str] = None,
):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                WITH next_step AS (
                    SELECT COALESCE(MAX(step_number), 0) + 1 AS step_number
                    FROM attack_chain
                    WHERE mission_id = %s
                )
                INSERT INTO attack_chain (
                    mission_id, step_number, agent_name, action, target, outcome, timestamp
                )
                SELECT
                    %s,
                    next_step.step_number,
                    %s,
                    %s,
                    %s,
                    %s,
                    COALESCE(%s, NOW())
                FROM next_step
                RETURNING *;
                """,
                (mission_id, mission_id, agent_name, action, target, outcome, timestamp),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def get_attack_chain_by_mission(mission_id: str):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM attack_chain
                WHERE mission_id = %s
                ORDER BY step_number ASC, timestamp ASC NULLS LAST;
                """,
                (mission_id,),
            )
            return cur.fetchall()
    finally:
        conn.close()
