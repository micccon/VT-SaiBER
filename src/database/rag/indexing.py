"""
Offline Indexing Pipeline Module
Walk source directories, load supported files, and chunk them into Chunk objects.

Routes files to a chunker by extension:
    .md          -> markdown_chunking (heading-aware)
    .txt / .pdf  -> simple_chunking   (character-based)
"""
# src/database/rag/indexing.py

import os
from pathlib import Path
from typing import List, Dict, Any, Callable

import pypdf

from .embedding import EmbeddingClient
from .models import Chunk, IngestionResult
from .rag_manager import clear_kb_by_source_dir, insert_kb_chunk
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
        for path in source_paths:
            if os.path.isdir(path):
                chunks.extend(await self._process_directory(path, metadata_base))
            elif os.path.isfile(path) and self._is_supported_file(path):
                chunks.extend(await self._process_single_file(path, path, metadata_base))
        return chunks

    async def ingest_into_knowledge_base(
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
        if not chunks:
            return IngestionResult(
                sources=resolved_sources,
                deleted_rows=deleted_rows,
                chunk_count=0,
                inserted_count=0,
                per_tool={},
                metadata_base=base_metadata,
            )

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

        return IngestionResult(
            sources=resolved_sources,
            deleted_rows=deleted_rows,
            chunk_count=len(chunks),
            inserted_count=inserted_count,
            per_tool=per_tool,
            metadata_base=base_metadata,
        )

    def _is_supported_file(self, file_path: str) -> bool:
        return file_path.lower().endswith(SUPPORTED_EXTENSIONS)

    def _select_strategy(self, path: str) -> ChunkingStrategy:
        if self.forced_strategy is not None:
            return self.forced_strategy
        if path.lower().endswith(".md"):
            return markdown_chunking
        return simple_chunking

    async def _process_directory(
        self,
        directory: str,
        metadata_base: Dict[str, Any],
    ) -> List[Chunk]:
        chunks: List[Chunk] = []
        for root, _, files in os.walk(directory):
            for name in files:
                if not self._is_supported_file(name):
                    continue
                full_path = os.path.join(root, name)
                chunks.extend(await self._process_single_file(full_path, directory, metadata_base))
        return chunks

    async def _process_single_file(
        self,
        path: str,
        source_root: str,
        metadata_base: Dict[str, Any],
    ) -> List[Chunk]:
        try:
            text = self._load_pdf(path) if path.lower().endswith(".pdf") else self._load_text_file(path)
        except Exception as exc:
            print(f"  ! skip {path}: {exc}")
            return []

        if not text.strip():
            return []

        doc_name = os.path.basename(path)
        rel_path = os.path.relpath(path, source_root) if os.path.isdir(source_root) else doc_name
        rel_path_posix = rel_path.replace(os.sep, "/")

        file_metadata = {
            **metadata_base,
            "source_path": path,
            "rel_path":    rel_path_posix,
            "tool":        self._derive_tool(rel_path_posix),
        }

        strategy = self._select_strategy(path)
        return strategy(
            doc_name=doc_name,
            text=text,
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
