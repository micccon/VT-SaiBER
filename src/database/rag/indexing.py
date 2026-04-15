"""
Offline Indexing Pipeline Module
Walk source directories, load supported files, and chunk them into Chunk objects.

Routes files to a chunker by extension:
    .md          -> markdown_chunking (heading-aware)
    .txt / .pdf  -> simple_chunking   (character-based)
"""
# src/database/rag/indexing.py

import hashlib
import os
from pathlib import Path
from typing import List, Dict, Any, Callable

import pypdf

from .embedding import EmbeddingClient
from .models import Chunk, IngestionResult, SourceFileRecord
from .rag_manager import (
    clear_kb_by_source_dir,
    delete_kb_by_source_path,
    get_indexed_source_files,
    insert_kb_chunk,
)
from .chunking import simple_chunking, markdown_chunking

ChunkingStrategy = Callable[..., List[Chunk]]

SUPPORTED_EXTENSIONS = (".txt", ".pdf", ".md")


class IndexingPipeline:
    """
    Offline indexing pipeline:
    - walk through source directories
    - load text/markdown/pdf files
    - chunk them into Chunk objects (no embeddings yet)
    """

    def __init__(
        self,
        chunking_strategy: ChunkingStrategy | None = None,
        max_chars: int = 800,
        overlap: int = 100,
    ):
        # If a strategy is explicitly provided, force-use it for every file.
        # Otherwise route by extension via _select_strategy.
        self.forced_strategy = chunking_strategy
        self.max_chars = max_chars
        self.overlap = overlap

    async def process_documents(
        self,
        source_paths: List[str],
        mode: str = "full",
        metadata_base: Dict[str, Any] | None = None,
    ) -> List[Chunk]:
        """
        Process all supported files under the given paths and return chunks.
        """
        if metadata_base is None:
            metadata_base = {}

        chunks: List[Chunk] = []
        for record in self._expand_source_paths(source_paths):
            chunks.extend(
                await self._process_single_file(
                    record.file_path,
                    record.source_root,
                    metadata_base,
                    text=record.text,
                    file_hash=record.file_hash,
                )
            )
        return chunks

    async def index_sources_into_knowledge_base(
        self,
        source_paths: List[str],
        *,
        embedding_client: EmbeddingClient,
        reset: bool = False,
        batch_size: int | None = None,
        metadata_base: Dict[str, Any] | None = None,
    ) -> IngestionResult:
        """
        End-to-end offline ingestion for supported source paths.

        This belongs in the indexing layer because it owns document walking,
        chunk production, and the chunk-to-KB indexing workflow.
        """
        resolved_sources = [str(Path(path)) for path in source_paths]
        base_metadata = dict(metadata_base or {})

        deleted_rows = 0
        if reset:
            for source_dir in resolved_sources:
                deleted_rows += clear_kb_by_source_dir(source_dir)

        chunks = await self.process_documents(
            source_paths=resolved_sources,
            metadata_base=base_metadata,
        )
        inserted_count, per_tool = await self._embed_and_insert_chunks(
            chunks,
            embedding_client=embedding_client,
            batch_size=batch_size,
        )

        return IngestionResult(
            sources=resolved_sources,
            deleted_rows=deleted_rows,
            chunk_count=len(chunks),
            inserted_count=inserted_count,
            per_tool=per_tool,
            metadata_base=base_metadata,
        )

    async def sync_sources_into_knowledge_base_incrementally(
        self,
        source_paths: List[str],
        *,
        embedding_client: EmbeddingClient,
        batch_size: int | None = None,
        metadata_base: Dict[str, Any] | None = None,
    ) -> IngestionResult:
        """
        Incrementally sync the knowledge base to the current source files.

        Only new or changed files are re-indexed. Files no longer present in the
        source set are removed from the knowledge_base table.
        """
        resolved_sources = [str(Path(path)) for path in source_paths]
        base_metadata = dict(metadata_base or {})

        current_records = self._expand_source_paths(resolved_sources)
        current_by_path = {record.file_path: record for record in current_records}
        indexed_by_path = get_indexed_source_files(resolved_sources)

        deleted_rows = 0
        removed_paths = sorted(set(indexed_by_path) - set(current_by_path))
        for source_path in removed_paths:
            deleted_rows += delete_kb_by_source_path(source_path)

        changed_records: List[SourceFileRecord] = []
        for source_path, record in current_by_path.items():
            indexed = indexed_by_path.get(source_path)
            if indexed is None:
                changed_records.append(record)
                continue
            if str(indexed.get("file_hash") or "") != record.file_hash:
                deleted_rows += delete_kb_by_source_path(source_path)
                changed_records.append(record)

        chunks: List[Chunk] = []
        for record in changed_records:
            chunks.extend(
                await self._process_single_file(
                    record.file_path,
                    record.source_root,
                    base_metadata,
                    text=record.text,
                    file_hash=record.file_hash,
                )
            )
        inserted_count, per_tool = await self._embed_and_insert_chunks(
            chunks,
            embedding_client=embedding_client,
            batch_size=batch_size,
        )

        return IngestionResult(
            sources=resolved_sources,
            deleted_rows=deleted_rows,
            chunk_count=len(chunks),
            inserted_count=inserted_count,
            per_tool=per_tool,
            metadata_base=base_metadata,
        )

    async def ingest_into_knowledge_base(
        self,
        source_paths: List[str],
        *,
        embedding_client: EmbeddingClient,
        reset: bool = False,
        batch_size: int | None = None,
        metadata_base: Dict[str, Any] | None = None,
    ) -> IngestionResult:
        """Compatibility wrapper for the old ingestion method name."""
        return await self.index_sources_into_knowledge_base(
            source_paths,
            embedding_client=embedding_client,
            reset=reset,
            batch_size=batch_size,
            metadata_base=metadata_base,
        )

    async def ingest_incremental_into_knowledge_base(
        self,
        source_paths: List[str],
        *,
        embedding_client: EmbeddingClient,
        batch_size: int | None = None,
        metadata_base: Dict[str, Any] | None = None,
    ) -> IngestionResult:
        """Compatibility wrapper for the old incremental ingestion name."""
        return await self.sync_sources_into_knowledge_base_incrementally(
            source_paths,
            embedding_client=embedding_client,
            batch_size=batch_size,
            metadata_base=metadata_base,
        )

    def _is_supported_file(self, file_path: str) -> bool:
        return file_path.lower().endswith(SUPPORTED_EXTENSIONS)

    def _select_strategy(self, path: str) -> ChunkingStrategy:
        if self.forced_strategy is not None:
            return self.forced_strategy
        if path.lower().endswith(".md"):
            return markdown_chunking
        return simple_chunking

    def _expand_source_paths(self, source_paths: List[str]) -> List[SourceFileRecord]:
        records: List[SourceFileRecord] = []
        for path in source_paths:
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for name in files:
                        if not self._is_supported_file(name):
                            continue
                        full_path = os.path.join(root, name)
                        try:
                            text = self._read_document(full_path)
                        except Exception as exc:
                            print(f"  ! skip {full_path}: {exc}")
                            continue
                        if not text.strip():
                            continue
                        records.append(
                            SourceFileRecord(
                                file_path=full_path,
                                source_root=path,
                                file_hash=self._hash_text(text),
                                text=text,
                            )
                        )
            elif os.path.isfile(path) and self._is_supported_file(path):
                try:
                    text = self._read_document(path)
                except Exception as exc:
                    print(f"  ! skip {path}: {exc}")
                    continue
                if not text.strip():
                    continue
                source_root = os.path.dirname(path) or "."
                records.append(
                    SourceFileRecord(
                        file_path=path,
                        source_root=source_root,
                        file_hash=self._hash_text(text),
                        text=text,
                    )
                )
        return records

    async def _process_single_file(
        self,
        path: str,
        source_root: str,
        metadata_base: Dict[str, Any],
        *,
        text: str | None = None,
        file_hash: str | None = None,
    ) -> List[Chunk]:
        try:
            document_text = text if text is not None else self._read_document(path)
        except Exception as exc:
            print(f"  ! skip {path}: {exc}")
            return []

        if not document_text.strip():
            return []

        doc_name = os.path.basename(path)
        rel_path = os.path.relpath(path, source_root) if os.path.isdir(source_root) else doc_name
        rel_path_posix = rel_path.replace(os.sep, "/")

        file_metadata = {
            **metadata_base,
            "source_path": path,
            "source_root": source_root,
            "rel_path":    rel_path_posix,
            "tool":        self._derive_tool(rel_path_posix),
            "file_hash":   file_hash or self._hash_text(document_text),
        }

        strategy = self._select_strategy(path)
        return strategy(
            doc_name=doc_name,
            text=document_text,
            max_chars=self.max_chars,
            overlap=self.overlap,
            metadata_base=file_metadata,
        )

    @staticmethod
    def _derive_tool(rel_path_posix: str) -> str:
        """First path segment is the tool name; falls back to filename stem."""
        head, _, tail = rel_path_posix.partition("/")
        if tail:
            return head
        return os.path.splitext(head)[0].split("_")[0]

    def _load_pdf(self, path: str) -> str:
        reader = pypdf.PdfReader(path)
        pages = []
        for page in reader.pages:
            try:
                pages.append(page.extract_text() or "")
            except Exception:
                continue
        return "\n".join(pages)

    def _load_text_file(self, path: str) -> str:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def _read_document(self, path: str) -> str:
        return self._load_pdf(path) if path.lower().endswith(".pdf") else self._load_text_file(path)

    def _hash_text(self, text: str) -> str:
        return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()

    async def _embed_and_insert_chunks(
        self,
        chunks: List[Chunk],
        *,
        embedding_client: EmbeddingClient,
        batch_size: int | None = None,
    ) -> tuple[int, Dict[str, int]]:
        if not chunks:
            return 0, {}

        texts = [chunk.chunk_text for chunk in chunks]
        embeddings = await embedding_client.embed_texts(
            texts,
            batch_size=batch_size,
        )

        inserted_count = 0
        per_tool: Dict[str, int] = {}
        for chunk, embedding in zip(chunks, embeddings):
            chunk.embedding = embedding
            insert_kb_chunk(chunk)
            inserted_count += 1

            tool = str(chunk.metadata.get("tool", "unknown"))
            per_tool[tool] = per_tool.get(tool, 0) + 1

        return inserted_count, per_tool
