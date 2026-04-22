# pytest tests/db_tests/test_incremental_indexing.py

import pytest
from pathlib import Path
from uuid import uuid4
import shutil

from src.database.rag.indexing import IndexingPipeline


class _FakeEmbeddingClient:
    async def embed_texts(self, texts, batch_size=None):
        return [[0.0] * 1024 for _ in texts]


@pytest.mark.asyncio
async def test_incremental_indexing_skips_unchanged_files(monkeypatch):
    tmp_dir = Path("tests/.tmp_incremental") / f"case_{uuid4().hex}"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    try:
        doc = tmp_dir / "test.txt"
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
            "src.database.rag.indexing.insert_kb_chunks",
            lambda chunks: inserted.extend(chunks) or len(chunks),
        )

        result = await pipeline.sync_sources_into_knowledge_base_incrementally(
            source_paths=[str(doc)],
            embedding_client=_FakeEmbeddingClient(),
            metadata_base={"corpus": "testbed_docs"},
        )

        assert result.inserted_count == 0
        assert result.deleted_rows == 0
        assert inserted == []
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_incremental_indexing_replaces_changed_and_removed_files(monkeypatch):
    tmp_dir = Path("tests/.tmp_incremental") / f"case_{uuid4().hex}"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    try:
        active = tmp_dir / "active.txt"
        active.write_text("hello world", encoding="utf-8")

        removed_path = str(tmp_dir / "removed.txt")

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
            "src.database.rag.indexing.insert_kb_chunks",
            lambda chunks: inserted.extend(chunks) or len(chunks),
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
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
