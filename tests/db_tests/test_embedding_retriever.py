# tests/db_tests/test_embedding_retriever.py

from typing import Any, Dict
import pytest
from dotenv import load_dotenv

from src.database.rag.rag_engine import RAGOrchestrator
from src.database.manager import get_connection

load_dotenv()


@pytest.mark.asyncio
async def test_indexing_pipeline_ingests_test_file():
    """
    End-to-end test:
    - Run RAGOrchestrator.index_knowledge_base_full on database/testbed_docs
    - Verify that at least one row from test.txt is stored in knowledge_base
    """
    # 1. Run indexing on the testbed_docs directory
    rag = RAGOrchestrator()
    await rag.index_knowledge_base_full(["src/database/testbed_docs"])

    # 2. Query the DB to check inserted rows
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT doc_name, chunk_text, metadata, embedding
                FROM knowledge_base
                WHERE metadata->>'source_path' LIKE %s
                ORDER BY id DESC;
                """,
                ("%test.txt%",),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    assert rows, "No rows for test.txt found in knowledge_base"

    found = False
    for row in rows:
        doc_name = row[0]
        content = row[1]
        metadata = row[2]
        embedding = row[3]

        # doc_name 應該是檔名本身
        assert doc_name == "test.txt"
        # 內容應該包含 "hello world"
        assert "hello world" in content
        # metadata 至少應該有 source_path
        assert isinstance(metadata, dict)
        assert "source_path" in metadata
        # embedding 應該是非空向量
        assert embedding is not None

        found = True
        break  # 找到一筆就夠了

    assert found, "Indexed row for test.txt not validated"


@pytest.mark.asyncio
async def test_rag_retriever_can_find_test_doc():
    rag = RAGOrchestrator()
    results = await rag.retrieve(query="hello world", source="kb", top_k=3)

    kb_results = results["kb_results"]
    assert kb_results

    found = any(r["doc_name"] == "test.txt" for r in kb_results)
    assert found, "RAG retrieval did not return chunk from test.txt"