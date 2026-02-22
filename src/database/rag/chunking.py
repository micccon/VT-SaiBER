# src/database/rag/chunking.py

from typing import List, Dict, Any
from .models import Chunk


def simple_chunking( doc_name: str, text: str, max_chars: int = 800, metadata_base: Dict[str, Any] | None = None) -> List[Chunk]:
    if metadata_base is None:
        metadata_base = {}

    chunks: List[Chunk] = []
    length = len(text)

    for i in range(0, length, max_chars):
        chunk_text = text[i : i + max_chars]

        if not chunk_text.strip():
            continue

        chunk = Chunk(
            doc_name=doc_name,
            chunk_text=chunk_text,
            embedding=[],
            metadata=dict(metadata_base),
        )
        chunks.append(chunk)

    return chunks
