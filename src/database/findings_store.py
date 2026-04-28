from __future__ import annotations

import json
import logging
from functools import lru_cache
from typing import Any, Dict

from psycopg2.extras import RealDictCursor

from src.database.connection import get_connection
from src.database.intelligence_format import build_intelligence_embedding_text

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_embedding_client():
    try:
        from src.database.rag.embedding import EmbeddingClient

        return EmbeddingClient()
    except Exception as exc:
        logger.warning("Embedding client unavailable for finding auto-embed: %s", exc)
        return None


def create_finding(mission_id, agent_name, finding_type, severity, target_ip, target_port, title, description, data=None, auto_embed=False):
    conn = get_connection()
    try:
        json_data = json.dumps(data) if data is not None else None
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO findings (
                    mission_id, agent_name, finding_type, severity, target_ip, target_port,
                    title, description, data
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *;
                """,
                (
                    mission_id,
                    agent_name,
                    finding_type,
                    severity,
                    target_ip,
                    target_port,
                    title,
                    description,
                    json_data,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        if auto_embed and row is not None:
            _embed_finding_row(row)
        return row
    finally:
        conn.close()


def get_findings():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings ORDER BY id;")
            return cur.fetchall()
    finally:
        conn.close()


def get_findings_by_mission(mission_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM findings WHERE mission_id = %s ORDER BY severity DESC;",
                (mission_id,),
            )
            return cur.fetchall()
    finally:
        conn.close()


def finding_exists_by_persistence_key(mission_id: str, persistence_key: str) -> bool:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM findings
                WHERE mission_id = %s
                  AND data->>'persistence_key' = %s
                LIMIT 1;
                """,
                (mission_id, persistence_key),
            )
            return cur.fetchone() is not None
    finally:
        conn.close()


def delete_finding(finding_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "DELETE FROM findings WHERE id = %s RETURNING *;",
                (finding_id,),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def _embed_finding_row(finding_row: Dict[str, Any]) -> None:
    embedding_client = _get_embedding_client()
    if embedding_client is None:
        return

    try:
        embedded_text = build_intelligence_embedding_text(
            str(finding_row.get("title") or "").strip(),
            str(finding_row.get("description") or "").strip(),
            finding_row.get("data") or {},
        )
        if not embedded_text.strip():
            return

        embedding_vector = embedding_client.embed_text_sync(embedded_text)
        create_finding_embedding(
            finding_id=finding_row["id"],
            embedding_vector=embedding_vector,
            embedded_text=embedded_text,
            embedding_model=embedding_client.provenance_tag(),
        )
    except Exception as exc:
        logger.warning("Failed to auto-embed finding %s: %s", finding_row.get("id"), exc)


def create_finding_embedding(finding_id, embedding_vector, embedded_text, embedding_model="BAAI/bge-large-en-v1.5"):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO findings_embeddings (finding_id, embedding, embedded_text, embedding_model)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (finding_id) DO UPDATE SET
                    embedding = EXCLUDED.embedding,
                    embedded_text = EXCLUDED.embedded_text,
                    embedding_model = EXCLUDED.embedding_model,
                    updated_at = NOW()
                RETURNING *;
                """,
                (finding_id, embedding_vector, embedded_text, embedding_model),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def get_finding_embedding(finding_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM findings_embeddings WHERE finding_id = %s;",
                (finding_id,),
            )
            return cur.fetchone()
    finally:
        conn.close()


def update_finding_embedding(finding_id, embedding_vector, embedded_text):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE findings_embeddings
                SET embedding = %s, embedded_text = %s, updated_at = NOW()
                WHERE finding_id = %s
                RETURNING *;
                """,
                (embedding_vector, embedded_text, finding_id),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def delete_finding_embedding(finding_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "DELETE FROM findings_embeddings WHERE finding_id = %s RETURNING *;",
                (finding_id,),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def get_all_findings_embeddings():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings_embeddings ORDER BY created_at DESC;")
            return cur.fetchall()
    finally:
        conn.close()
