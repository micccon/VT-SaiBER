from dataclasses import dataclass


@dataclass
class LibrarianSource:
    type: str      # "kb" | "osint"
    name: str      # doc_name 或 domain/URL
    similarity: float | None
    extra: dict

@dataclass
class LibrarianAnswer:
    answer: str
    sources: list[LibrarianSource]
    confidence: float