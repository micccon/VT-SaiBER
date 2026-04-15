import pytest

from src.database.rag.indexing import IndexingPipeline


class _FakeEmbeddingClient:
    async def embed_texts(self, texts, batch_size=None):
        return [[0.0] * 1024 for _ in texts]


@pytest.mark.asyncio
async def test_incremental_indexing_skips_unchanged_files(tmp_path, monkeypatch):
    doc = tmp_path / "test.txt"
    doc.write_text("hello world", encoding="utf-8")

    pipeline = IndexingPipeline()
    current_record = pipeline._expand_source_paths([str(doc)])[0]

    monkeypatch.setattr(
        "src.database.rag.indexing.get_indexed_source_files",
        lambda source_paths: {
            current_record.file_path: {"file_hash": current_record.file_hash}
        },
    )
    monkeypatch.setattr(
        "src.database.rag.indexing.delete_kb_by_source_path",
        lambda source_path: 0,
    )
    inserted = []
    monkeypatch.setattr(
        "src.database.rag.indexing.insert_kb_chunk",
        lambda chunk: inserted.append(chunk),
    )

    result = await pipeline.sync_sources_into_knowledge_base_incrementally(
        source_paths=[str(doc)],
        embedding_client=_FakeEmbeddingClient(),
        metadata_base={"corpus": "testbed_docs"},
    )

    assert result.inserted_count == 0
    assert result.deleted_rows == 0
    assert inserted == []


@pytest.mark.asyncio
async def test_incremental_indexing_replaces_changed_and_removed_files(tmp_path, monkeypatch):
    active = tmp_path / "active.txt"
    active.write_text("hello world", encoding="utf-8")

    removed_path = str(tmp_path / "removed.txt")

    pipeline = IndexingPipeline()
    current_record = pipeline._expand_source_paths([str(active)])[0]

    deleted_paths = []
    monkeypatch.setattr(
        "src.database.rag.indexing.get_indexed_source_files",
        lambda source_paths: {
            current_record.file_path: {"file_hash": "old-hash"},
            removed_path: {"file_hash": "removed-hash"},
        },
    )
    monkeypatch.setattr(
        "src.database.rag.indexing.delete_kb_by_source_path",
        lambda source_path: deleted_paths.append(source_path) or 1,
    )
    inserted = []
    monkeypatch.setattr(
        "src.database.rag.indexing.insert_kb_chunk",
        lambda chunk: inserted.append(chunk),
    )

    result = await pipeline.sync_sources_into_knowledge_base_incrementally(
        source_paths=[str(active)],
        embedding_client=_FakeEmbeddingClient(),
        metadata_base={"corpus": "testbed_docs"},
    )

    assert result.inserted_count == len(inserted)
    assert result.inserted_count >= 1
    assert result.deleted_rows == 2
    assert current_record.file_path in deleted_paths
    assert removed_path in deleted_paths
