# src/database/rag/rag_manager.py

import json
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
