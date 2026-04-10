# src/database/rag/rag_manager.py
"""
RAG Database Operations Module
Handle all knowledge_base table operations: insert, search, delete, update.
Uses existing manager.py connection but provides RAG-specific interface.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from psycopg2.extras import RealDictCursor

from src.database.manager import get_connection
from .models import Chunk


def insert_kb_chunk(chunk: Chunk):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO knowledge_base (doc_name, chunk_text, embedding, metadata)
                VALUES (%s, %s, %s, %s)
                RETURNING *;
                """,
                (
                    chunk.doc_name,
                    chunk.chunk_text,
                    chunk.embedding,
                    json.dumps(chunk.metadata),
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def search_by_embedding(
    query_embedding: List[float],
    top_k: int = 5,
    filters: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Filters can be added later once metadata query patterns stabilize.
            cur.execute(
                """
                SELECT id, doc_name, chunk_text, metadata, embedding,
                       1 - (embedding <=> %s::vector) AS similarity
                FROM knowledge_base
                ORDER BY embedding <-> %s::vector
                LIMIT %s;
                """,
                (query_embedding, query_embedding, top_k),
            )
            rows = cur.fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def clear_kb_by_source_dir(source_dir: str | None) -> int:
    """Delete KB rows by source path, or clear the table when source_dir is None."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if source_dir is None:
                cur.execute("DELETE FROM knowledge_base;")
            else:
                cur.execute(
                    """
                    DELETE FROM knowledge_base
                    WHERE metadata->>'source_path' LIKE %s;
                    """,
                    (f"%{source_dir}%",),
                )
            deleted = cur.rowcount
        conn.commit()
        return deleted
    finally:
        conn.close()


def clear_knowledge_base() -> int:
    """Delete every row from the knowledge_base table."""
    return clear_kb_by_source_dir(None)
