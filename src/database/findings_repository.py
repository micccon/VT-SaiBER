from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from psycopg2.extras import RealDictCursor

from src.database.connection import get_connection


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
