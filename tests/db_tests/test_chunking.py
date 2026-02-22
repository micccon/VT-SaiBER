# tests/db_tests/test_chunking.py

from typing import Any, Dict

from src.database.rag.models import Chunk
from src.database.rag.chunking import simple_chunking
from src.database.rag.rag_manager import insert_kb_chunk


def test_simple_chunking_basic():
    doc_name = "test_document"
    # Make a long text so that it will be split into multiple chunks
    text = "This is a test text for chunking. " * 50
    max_chars = 50
    metadata_base: Dict[str, Any] = {"source": "pytest"}

    chunks = simple_chunking(
        doc_name=doc_name,
        text=text,
        max_chars=max_chars,
        metadata_base=metadata_base,
    )

    # There should be at least 2 chunks
    assert len(chunks) >= 2

    # All items should be Chunk instances
    assert all(isinstance(c, Chunk) for c in chunks)

    # Check that metadata contains our base metadata
    for c in chunks:
        assert c.metadata.get("source") == "pytest"
        assert c.doc_name == doc_name
        assert isinstance(c.chunk_text, str)
        assert isinstance(c.embedding, list)


def test_insert_kb_chunk_smoke():
    """
    Smoke test: inserting a single Chunk into knowledge_base should not raise errors.
    Optionally, you can later extend this to assert that the returned row has expected values.
    """
    doc_name = "insert_test_document"
    text = "This is a short text used to test DB insertion via insert_kb_chunk."
    metadata: Dict[str, Any] = {"source": "pytest_insert"}
    fake_embedding = [0.0] * 1536


    chunk = Chunk(
        doc_name=doc_name,
        chunk_text=text,
        embedding=fake_embedding,  # you can later fill this with a real embedding
        metadata=metadata,
    )

    row = insert_kb_chunk(chunk)

    # At least check that something is returned and doc_name matches
    assert row is not None
    assert row["doc_name"] == doc_name
