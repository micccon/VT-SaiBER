"""
Document Chunking Module
Split long documents into smaller chunks (Chunk objects).

Strategies:
    - simple_chunking:   character-based with word-boundary snapping (default for .txt / .pdf)
    - markdown_chunking: heading-aware split, falling back to simple_chunking for oversized sections
"""

# src/database/rag/chunking.py

import re
from typing import List, Dict, Any, Tuple

from .models import Chunk


HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")


def simple_chunking(
    doc_name: str,
    text: str,
    max_chars: int = 800,
    overlap: int = 100,
    metadata_base: Dict[str, Any] | None = None,
) -> List[Chunk]:
    """
    Character-based chunking with optional overlap and word-boundary snapping.

    Args:
        doc_name: Identifier for the source document.
        text: Full document text.
        max_chars: Maximum characters per chunk (hard upper bound).
        overlap: Number of characters to overlap between consecutive chunks.
        metadata_base: Base metadata copied into each Chunk.
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
            chunks.append(Chunk(
                doc_name=doc_name,
                chunk_text=chunk_text,
                embedding=[],
                metadata=dict(metadata_base),
            ))

        if end >= length:
            break
        start = max(0, end - overlap)

    return chunks


def _split_markdown_sections(text: str) -> List[Tuple[str, str]]:
    """
    Walk markdown text and group lines under their nearest heading hierarchy.

    Returns a list of (section_path, body) tuples where section_path is a
    breadcrumb like "Target > URL" built from h1..h6 ancestors.
    """
    sections: List[Tuple[str, str]] = []
    heading_stack: List[Tuple[int, str]] = []
    current_lines: List[str] = []

    def flush() -> None:
        if not current_lines:
            return
        body = "\n".join(current_lines).strip()
        if not body:
            return
        path = " > ".join(title for _, title in heading_stack)
        sections.append((path, body))

    for line in text.splitlines():
        match = HEADING_RE.match(line)
        if not match:
            current_lines.append(line)
            continue

        flush()
        current_lines = []

        level = len(match.group(1))
        title = match.group(2).strip()

        while heading_stack and heading_stack[-1][0] >= level:
            heading_stack.pop()
        heading_stack.append((level, title))

        current_lines.append(line)

    flush()
    return sections


def markdown_chunking(
    doc_name: str,
    text: str,
    max_chars: int = 800,
    overlap: int = 100,
    metadata_base: Dict[str, Any] | None = None,
) -> List[Chunk]:
    """
    Heading-aware chunker for markdown.

    1. Split text into sections by markdown headings (#, ##, ###, ...).
    2. Each section becomes one chunk if it fits within max_chars.
    3. Oversized sections are re-chunked via simple_chunking, preserving the
       section breadcrumb in metadata so retrieval can cite "Tool > Section".

    Falls through to simple_chunking entirely when no headings are present.
    """
    if metadata_base is None:
        metadata_base = {}

    sections = _split_markdown_sections(text)
    if not sections:
        return simple_chunking(doc_name, text, max_chars, overlap, metadata_base)

    chunks: List[Chunk] = []
    for section_path, body in sections:
        section_metadata = {**metadata_base, "section": section_path}

        if len(body) <= max_chars:
            chunks.append(Chunk(
                doc_name=doc_name,
                chunk_text=body,
                embedding=[],
                metadata=section_metadata,
            ))
            continue

        chunks.extend(simple_chunking(
            doc_name=doc_name,
            text=body,
            max_chars=max_chars,
            overlap=overlap,
            metadata_base=section_metadata,
        ))

    return chunks
