# src/database/rag/models.py

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
