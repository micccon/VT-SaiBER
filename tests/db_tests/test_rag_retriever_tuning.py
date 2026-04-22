# pytest tests/db_tests/test_rag_retriever_tuning.py

import pytest
from src.database.rag.retriever import RAGRetriever


class _FakeEmbeddingClient:
    async def embed_text(self, text):
        return [0.0] * 1024


@pytest.mark.asyncio
async def test_retriever_reranks_by_tool_and_doc_match(monkeypatch):
    retriever = RAGRetriever(_FakeEmbeddingClient())

    monkeypatch.setattr(
        "src.database.rag.retriever.search_by_embedding",
        lambda *args, **kwargs: [
            {
                "doc_name": "generic_notes.txt",
                "chunk_text": "generic",
                "metadata": {"tool": "notes", "rel_path": "notes/generic_notes.txt"},
                "similarity": 0.80,
            },
            {
                "doc_name": "sqlmap_usage.md",
                "chunk_text": "sqlmap options",
                "metadata": {"tool": "sqlmap", "rel_path": "sqlmap/Usage.md"},
                "similarity": 0.78,
            },
        ],
    )

    results = await retriever.retrieve_from_kb("sqlmap technique", top_k=1)
    assert results[0]["doc_name"] == "sqlmap_usage.md"
    assert results[0]["score"] >= results[0]["similarity"]


@pytest.mark.asyncio
async def test_findings_rerank_boosts_severity(monkeypatch):
    retriever = RAGRetriever(_FakeEmbeddingClient())

    monkeypatch.setattr(
        "src.database.rag.retriever.search_similar_findings",
        lambda *args, **kwargs: [
            {"id": 1, "severity": "medium", "similarity": 0.80, "created_at": "2026-04-01T00:00:00+00:00"},
            {"id": 2, "severity": "critical", "similarity": 0.78, "created_at": "2026-04-20T00:00:00+00:00"},
        ],
    )

    results = await retriever.retrieve_from_findings("exploit path", top_k=1)
    assert results[0]["id"] == 2
