from __future__ import annotations

import uuid

import pytest

from scripts.tests.database.live_helpers import (
    insert_live_kb_chunk,
    require_live_embeddings,
    run_live_kb_retrieval,
    step,
)


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.kb
async def test_live_rag_kb_vector_retrieval_round_trip(kb_source_prefix: str) -> None:
    step("Creating a real embedding client for KB vector retrieval")
    require_live_embeddings()
    unique_token = f"vt-saiber-live-kb-{uuid.uuid4().hex[:8]}"
    chunk_text = (
        f"{unique_token} vsftpd 2.3.4 backdoor exploit guidance mentions the "
        "service backdoor and interactive shell behavior."
    )
    step(f"Embedding and inserting a KB chunk with unique token {unique_token}")
    embedding_client, _ = await insert_live_kb_chunk(
        kb_source_prefix,
        "pytest-live-kb.md",
        chunk_text,
    )

    step("Running live KB retrieval through the RAG retriever")
    results = await run_live_kb_retrieval(
        f"{unique_token} vsftpd 2.3.4 backdoor exploit",
        embedding_client,
        top_k=3,
    )
    kb_results = results["kb_results"]
    print(
        "[live-kb] results="
        + ", ".join(
            f"{item['doc_name']} score={float(item.get('score') or item.get('similarity') or 0.0):.3f}"
            for item in kb_results
        )
    )

    assert kb_results
    assert kb_results[0]["doc_name"] == "pytest-live-kb.md"
    assert unique_token in kb_results[0]["chunk_text"]
