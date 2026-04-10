# src/database/rag/models.py

"""
RAG Data Models Module
Define core data structures for RAG system: Chunk represents a document fragment with metadata and embeddings.
Used by indexing and retrieval pipelines.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any

@dataclass
class Chunk:
    """
    @dataclass can automatically generate __init__, __repr__, and other methods.
    """
    doc_name: str
    chunk_text: str
    embedding: List[float]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)  # transform dataclass to dict for easier insertion into DB


@dataclass
class IngestionResult:
    """Summary produced by knowledge-base ingestion/indexing runs."""

    sources: List[str]
    deleted_rows: int
    chunk_count: int
    inserted_count: int
    per_tool: Dict[str, int]
    metadata_base: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
