"""
Document Chunking Module
Split long documents into smaller chunks (Chunk objects).
Supports simple character-based chunking, extensible for semantic/hierarchical strategies.
"""

# src/database/rag/chunking.py

from typing import List, Dict, Any
from .models import Chunk


def simple_chunking(
    doc_name: str,
    text: str,
    max_chars: int = 800,
    overlap: int = 100,
    metadata_base: Dict[str, Any] | None = None,
) -> List[Chunk]:
    """
    Simple character-based chunking with optional overlap and basic word-boundary snapping.

    Args:
        doc_name: Identifier for the source document.
        text: Full document text.
        max_chars: Maximum characters per chunk (hard upper bound).
        overlap: Number of characters to overlap between consecutive chunks.
        metadata_base: Base metadata copied into each Chunk.

    Returns:
        List[Chunk]: Chunk objects with empty embeddings ready for indexing.
    """
    if metadata_base is None:
        metadata_base = {}

    chunks: List[Chunk] = []
    length = len(text)

    if length == 0:
        return chunks

    overlap = max(0, min(overlap, max_chars // 2))

    start = 0
    while start < length:
        end = min(start + max_chars, length)
        chunk_text = text[start:end]

        if end < length:
            last_space = chunk_text.rfind(" ")
            if last_space != -1 and last_space > max_chars * 0.6:
                end = start + last_space
                chunk_text = text[start:end]

        if chunk_text.strip():
            chunk = Chunk(
                doc_name=doc_name,
                chunk_text=chunk_text,
                embedding=[],
                metadata=dict(metadata_base),
            )
            chunks.append(chunk)

        if end >= length:
            break
        start = max(0, end - overlap)

    return chunks
