from __future__ import annotations

import json
import logging
from functools import lru_cache
from typing import Any, Dict, List, Optional

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


def create_finding(
    mission_id,
    agent_name,
    finding_type,
    severity,
    target_ip,
    target_port,
    title,
    description,
    data=None,
    auto_embed=False,
):
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


def create_finding_embedding(
    finding_id,
    embedding_vector,
    embedded_text,
    embedding_model="BAAI/bge-large-en-v1.5",
):
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


def search_similar_findings(
    embedding_vector,
    limit: int = 5,
    threshold: float = 0.7,
    filters: Optional[Dict[str, Any]] = None,
    embedding_model: str | None = None,
):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            where_clauses = ["1 - (fe.embedding <=> %s::vector) >= %s"]
            params: List[Any] = [embedding_vector, threshold]

            for key, value in dict(filters or {}).items():
                if value is None:
                    continue
                if key in {"mission_id", "agent_name", "finding_type", "severity", "target_ip"}:
                    where_clauses.append(f"f.{key} = %s")
                    params.append(value)
                elif key == "target_port":
                    where_clauses.append("f.target_port = %s")
                    params.append(int(value))
            if embedding_model:
                where_clauses.append("fe.embedding_model = %s")
                params.append(embedding_model)

            cur.execute(
                """
                SELECT
                    fe.finding_id,
                    f.id,
                    f.mission_id,
                    f.agent_name,
                    f.finding_type,
                    f.severity,
                    f.target_ip,
                    f.target_port,
                    f.title,
                    f.description,
                    f.data,
                    f.created_at,
                    1 - (fe.embedding <=> %s::vector) AS similarity
                FROM findings_embeddings fe
                JOIN findings f ON fe.finding_id = f.id
                WHERE """ + " AND ".join(where_clauses) + """
                ORDER BY fe.embedding <=> %s::vector
                LIMIT %s;
                """,
                [embedding_vector, *params, embedding_vector, limit],
            )
            return cur.fetchall()
    finally:
        conn.close()


def search_findings_text(
    query: str,
    *,
    limit: int = 5,
    filters: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    tokens = [token.strip() for token in str(query or "").lower().replace("/", " ").split() if len(token.strip()) >= 3]
    tokens = tokens[:8]

    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            where_clauses = ["1=1"]
            params: List[Any] = []

            for key, value in dict(filters or {}).items():
                if value is None:
                    continue
                if key in {"mission_id", "agent_name", "finding_type", "severity", "target_ip"}:
                    where_clauses.append(f"f.{key} = %s")
                    params.append(value)
                elif key == "target_port":
                    where_clauses.append("f.target_port = %s")
                    params.append(int(value))

            token_clauses: List[str] = []
            for token in tokens:
                token_clauses.append(
                    "(LOWER(COALESCE(f.title, '')) LIKE %s OR LOWER(COALESCE(f.description, '')) LIKE %s OR LOWER(COALESCE(f.data::text, '')) LIKE %s)"
                )
                params.extend([f"%{token}%", f"%{token}%", f"%{token}%"])

            if token_clauses:
                where_clauses.append("(" + " OR ".join(token_clauses) + ")")

            cur.execute(
                """
                SELECT
                    f.id,
                    f.mission_id,
                    f.agent_name,
                    f.finding_type,
                    f.severity,
                    f.target_ip,
                    f.target_port,
                    f.title,
                    f.description,
                    f.data,
                    f.created_at
                FROM findings f
                WHERE """ + " AND ".join(where_clauses) + """
                ORDER BY f.created_at DESC
                LIMIT %s;
                """,
                [*params, limit],
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    normalized: List[Dict[str, Any]] = []
    for row in rows:
        data = row.get("data")
        text = " ".join(
            part
            for part in [
                str(row.get("title") or "").strip(),
                str(row.get("description") or "").strip(),
                json.dumps(data or {}, default=str),
            ]
            if part
        )
        matched = sum(1 for token in tokens if token and token in text.lower())
        normalized_row = dict(row)
        normalized_row["similarity"] = round(min(0.95, 0.35 + (0.08 * matched)), 6) if tokens else 0.35
        normalized_row["score"] = normalized_row["similarity"]
        normalized.append(normalized_row)

    normalized.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
    return normalized[:limit]


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
