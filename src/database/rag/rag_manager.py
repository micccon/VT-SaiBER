# src/database/rag/rag_manager.py
"""
RAG Database Operations Module
Handle all knowledge_base table operations: insert, search, delete, update.
Uses the shared database connection module and provides a RAG-specific interface.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Sequence

from psycopg2.extras import RealDictCursor, execute_values

from src.database.connection import get_connection
from .models import Chunk


def insert_kb_chunk(chunk: Chunk):
    """Insert a single KB chunk with its persisted embedding and metadata."""

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


def insert_kb_chunks(chunks: Sequence[Chunk]) -> int:
    """Bulk insert KB chunks to keep indexing faster than row-by-row writes."""

    if not chunks:
        return 0

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            execute_values(
                cur,
                """
                INSERT INTO knowledge_base (doc_name, chunk_text, embedding, metadata)
                VALUES %s;
                """,
                [
                    (
                        chunk.doc_name,
                        chunk.chunk_text,
                        chunk.embedding,
                        json.dumps(chunk.metadata),
                    )
                    for chunk in chunks
                ],
            )
        conn.commit()
        return len(chunks)
    finally:
        conn.close()


def search_by_embedding(
    query_embedding: List[float],
    top_k: int = 5,
    filters: Dict[str, Any] | None = None,
    min_similarity: float = 0.0,
) -> List[Dict[str, Any]]:
    """Search KB chunks by vector similarity with optional metadata filters."""

    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            where_clauses = ["1 - (embedding <=> %s::vector) >= %s"]
            params: List[Any] = [query_embedding, float(min_similarity)]
            filter_clauses, filter_params = _metadata_filter_clauses(filters)
            where_clauses.extend(filter_clauses)
            params.extend(filter_params)

            cur.execute(
                """
                SELECT id, doc_name, chunk_text, metadata, embedding,
                       1 - (embedding <=> %s::vector) AS similarity
                FROM knowledge_base
                WHERE """ + " AND ".join(where_clauses) + """
                ORDER BY embedding <=> %s::vector
                LIMIT %s;
                """,
                [query_embedding, *params, query_embedding, top_k],
            )
            rows = cur.fetchall()
        return rows
    finally:
        conn.close()


def search_by_text(
    query: str,
    *,
    top_k: int = 5,
    filters: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    """Lexically search KB chunks when query embeddings are unavailable."""

    tokens = [
        token.strip()
        for token in str(query or "").lower().replace("/", " ").replace("_", " ").split()
        if len(token.strip(" ,.:;()[]{}")) >= 3
    ][:8]

    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            where_clauses = ["1=1"]
            filter_clauses, params = _metadata_filter_clauses(filters)
            where_clauses.extend(filter_clauses)

            token_clauses: List[str] = []
            for token in tokens:
                # Search all text-bearing columns we use for librarian context.
                token_clauses.append(
                    "(LOWER(COALESCE(doc_name, '')) LIKE %s OR LOWER(COALESCE(chunk_text, '')) LIKE %s OR LOWER(COALESCE(metadata::text, '')) LIKE %s)"
                )
                params.extend([f"%{token}%", f"%{token}%", f"%{token}%"])

            if token_clauses:
                where_clauses.append("(" + " OR ".join(token_clauses) + ")")

            cur.execute(
                """
                SELECT id, doc_name, chunk_text, metadata, embedding
                FROM knowledge_base
                WHERE """ + " AND ".join(where_clauses) + """
                ORDER BY created_at DESC
                LIMIT %s;
                """,
                [*params, top_k],
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    normalized: List[Dict[str, Any]] = []
    for row in rows:
        # Give lexical hits a synthetic score so downstream reranking can stay uniform.
        haystack = " ".join(
            [
                str(row.get("doc_name") or "").lower(),
                str(row.get("chunk_text") or "").lower(),
                str(row.get("metadata") or "").lower(),
            ]
        )
        matched = sum(1 for token in tokens if token and token in haystack)
        normalized_row = dict(row)
        normalized_row["similarity"] = round(min(0.9, 0.32 + (0.09 * matched)), 6) if tokens else 0.32
        normalized_row["score"] = normalized_row["similarity"]
        normalized.append(normalized_row)

    normalized.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
    return normalized[:top_k]


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


def delete_kb_by_source_path(source_path: str) -> int:
    """Delete KB rows for one exact source file path."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM knowledge_base
                WHERE metadata->>'source_path' = %s;
                """,
                (source_path,),
            )
            deleted = cur.rowcount
        conn.commit()
        return deleted
    finally:
        conn.close()


def get_indexed_source_files(source_paths: List[str] | None = None) -> Dict[str, Dict[str, Any]]:
    """
    Return one row per indexed source file keyed by metadata.source_path.

    file_hash is read from chunk metadata so incremental sync can detect which
    files changed since the last ingestion run.
    """
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    metadata->>'source_path' AS source_path,
                    metadata->>'file_hash' AS file_hash,
                    metadata->>'embedding_provider' AS embedding_provider,
                    metadata->>'embedding_model' AS embedding_model,
                    metadata->>'embedding_dimensions' AS embedding_dimensions,
                    metadata->>'embedding_provenance' AS embedding_provenance,
                    MIN(doc_name) AS doc_name,
                    COUNT(*) AS chunk_count
                FROM knowledge_base
                WHERE metadata ? 'source_path'
                GROUP BY
                    metadata->>'source_path',
                    metadata->>'file_hash',
                    metadata->>'embedding_provider',
                    metadata->>'embedding_model',
                    metadata->>'embedding_dimensions',
                    metadata->>'embedding_provenance';
                """
            )
            rows = cur.fetchall()
        conn.commit()
    finally:
        conn.close()

    indexed: Dict[str, Dict[str, Any]] = {}
    requested = list(source_paths or [])
    for row in rows:
        source_path = str(row.get("source_path") or "")
        if not source_path:
            continue

        if requested and not any(_source_path_matches(source_path, candidate) for candidate in requested):
            continue

        # Include embedding provenance so model/dimension changes can trigger reindexing.
        indexed[source_path] = {
            "file_hash": row.get("file_hash"),
            "doc_name": row.get("doc_name"),
            "chunk_count": int(row.get("chunk_count") or 0),
            "embedding_provider": row.get("embedding_provider"),
            "embedding_model": row.get("embedding_model"),
            "embedding_dimensions": row.get("embedding_dimensions"),
            "embedding_provenance": row.get("embedding_provenance"),
        }

    return indexed


def _source_path_matches(source_path: str, candidate: str) -> bool:
    """Match exact files or every indexed file under a requested source directory."""

    if source_path == candidate:
        return True
    normalized = source_path.replace("\\", "/")
    normalized_candidate = candidate.replace("\\", "/").rstrip("/")
    return normalized.startswith(f"{normalized_candidate}/")


def _metadata_filter_clauses(filters: Dict[str, Any] | None) -> tuple[List[str], List[Any]]:
    """Convert metadata filters into SQL fragments shared by vector and lexical search."""

    clauses: List[str] = []
    params: List[Any] = []
    metadata_filters = dict(filters or {})

    source_path_prefix = metadata_filters.pop("source_path_prefix", None)
    if source_path_prefix:
        clauses.append("metadata->>'source_path' LIKE %s")
        params.append(f"{str(source_path_prefix)}%")

    for key, value in metadata_filters.items():
        if value is None:
            continue
        # Lists map to SQL ANY() so callers can pass multiple acceptable values.
        if isinstance(value, (list, tuple, set)):
            normalized = [str(item) for item in value if item is not None]
            if not normalized:
                continue
            clauses.append("metadata->>%s = ANY(%s)")
            params.extend([str(key), normalized])
        else:
            clauses.append("metadata->>%s = %s")
            params.extend([str(key), str(value)])

    return clauses, params
