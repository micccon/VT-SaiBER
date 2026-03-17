"""
Offline Indexing Pipeline Module
Load documents and chunk them into Chunk objects.
Supports full and incremental indexing with file hash tracking.
"""
# src/database/rag/indexing.py

import os
import hashlib
from typing import List, Dict, Any, Callable
import pypdf

from .models import Chunk
from .chunking import simple_chunking
from .rag_manager import clear_kb_by_source_dir

ChunkingStrategy = Callable[[str, str, int, int, Dict[str, Any] | None], List[Chunk]]


class IndexingPipeline:
    """
    Offline indexing pipeline:
    - walk through source directories
    - load text/pdf files
    - chunk them into Chunk objects
    """

    def __init__(
        self,
        chunking_strategy: ChunkingStrategy = simple_chunking,
        max_chars: int = 800,
        overlap: int = 100,
    ):
        self.chunking_strategy = chunking_strategy
        self.max_chars = max_chars
        self.overlap = overlap
        self.file_hashes: Dict[str, str] = {}

    async def process_documents(
        self,
        source_paths: List[str],
        mode: str = "full",
        metadata_base: Dict[str, Any] | None = None,
    ) -> List[Chunk]:
        """
        Process all supported files under the given directories and return chunks.

        Args:
            source_paths: List of directories or files to process.
            mode: "full" or "incremental" (for future use).
            metadata_base: Base metadata to attach to each chunk.

        Returns:
            List of Chunk objects without embeddings.
        """
        if metadata_base is None:
            metadata_base = {}

        chunks = []
        for path in source_paths:
            if os.path.isdir(path):
                chunks.extend(await self._process_directory(path, metadata_base))
            elif os.path.isfile(path) and self._is_supported_file(path):
                chunks.extend(await self._process_single_file(path, metadata_base))
        return chunks

    def _is_supported_file(self, file_path: str) -> bool:
        """Check if file type is supported."""
        lower_path = file_path.lower()
        return lower_path.endswith((".txt", ".pdf"))

    async def _process_directory(self, directory: str, metadata_base: Dict[str, Any]) -> List[Chunk]:
        """Process all supported files in a directory."""
        chunks = []
        for root, _, files in os.walk(directory):
            for name in files:
                ext = name.lower()
                if not (ext.endswith(".txt") or ext.endswith(".pdf")):
                    continue
                full_path = os.path.join(root, name)
                chunks.extend(await self._process_single_file(full_path, metadata_base))
        return chunks

    async def _process_single_file(self, path: str, metadata_base: Dict[str, Any]) -> List[Chunk]:
        """Process a single file and return its chunks."""
        try:
            text = self._load_pdf(path) if path.lower().endswith(".pdf") else self._load_text_file(path)
        except Exception:
            return []  # Skip files that can't be read

        if not text.strip():
            return []

        doc_name = os.path.basename(path)
        chunks = self.chunking_strategy(
            doc_name=doc_name,
            text=text,
            max_chars=self.max_chars,
            overlap=self.overlap,
            metadata_base={**metadata_base, "source_path": path},
        )
        return chunks

    def _load_pdf(self, path: str) -> str:
        """Load PDF file content."""
        reader = pypdf.PdfReader(path)
        return "\n".join(
            page.extract_text() or "" for page in reader.pages
        )

    def _load_text_file(self, path: str) -> str:
        """Load text file content."""
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

