# src/database/rag/rag_engine.py

"""
RAG Orchestrator Module
Main entry point coordinating all RAG sub-modules (embedding, indexing, retrieval).
Provides high-level API for agents and CLI tools.
"""

from __future__ import annotations

from typing import Optional, Dict, Any, List

from .embedding import EmbeddingClient
from .indexing import IndexingPipeline
from .retriever import RAGRetriever
from .rag_manager import clear_knowledge_base

DEFAULT_KB_SOURCE_DIR = "src/database/testbed_docs"


class RAGOrchestrator:

    def __init__(self):
        """Initialize all RAG components."""
        self.embedding_client = EmbeddingClient()
        self.retriever = RAGRetriever(
            embedding_client=self.embedding_client
        )

    async def ingest_sources(
        self,
        source_dirs: Optional[List[str]] = None,
        *,
        reset: bool = False,
        max_chars: int = 800,
        overlap: int = 100,
        batch_size: Optional[int] = None,
        metadata_base: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Unified ingestion entrypoint for knowledge-base sources.

        rag_engine intentionally stays orchestration-only, so the actual
        chunking, embedding, and DB indexing work is delegated to the indexing
        pipeline.
        """
        resolved_sources = source_dirs or [DEFAULT_KB_SOURCE_DIR]
        base_metadata = dict(metadata_base or {})
        base_metadata.setdefault("corpus", "testbed_docs")

        indexing_pipeline = IndexingPipeline(
            max_chars=max_chars,
            overlap=overlap,
        )
        result = await indexing_pipeline.ingest_into_knowledge_base(
            source_paths=resolved_sources,
            embedding_client=self.embedding_client,
            reset=reset,
            batch_size=batch_size,
            metadata_base=base_metadata,
        )
        return result.to_dict()

    # ===== Offline Pipeline =====

    async def index_knowledge_base_full(
        self,
        source_dirs: Optional[List[str]] = None,
        *,
        max_chars: int = 800,
        overlap: int = 100,
        batch_size: Optional[int] = None,
        metadata_base: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Full indexing: clear old data and re-index all files.
        Suitable for initial setup or a full rebuild after source moves.
        """
        print("[RAG] Starting full knowledge base indexing...")

        clear_knowledge_base()
        result = await self.ingest_sources(
            source_dirs=source_dirs,
            reset=False,
            max_chars=max_chars,
            overlap=overlap,
            batch_size=batch_size,
            metadata_base=metadata_base,
        )
        print(
            f"[RAG] Knowledge base indexing completed - "
            f"{result['inserted_count']} chunks processed"
        )
        return result

    async def index_knowledge_base_incremental(
        self,
        source_dirs: Optional[List[str]] = None,
        *,
        max_chars: int = 800,
        overlap: int = 100,
        batch_size: Optional[int] = None,
        metadata_base: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Incremental indexing entrypoint.

        This currently re-ingests requested sources without a pre-clear. If you
        want a clean rebuild per source, call ingest_sources(..., reset=True).
        """
        print("[RAG] Starting incremental knowledge base indexing...")
        result = await self.ingest_sources(
            source_dirs=source_dirs,
            reset=False,
            max_chars=max_chars,
            overlap=overlap,
            batch_size=batch_size,
            metadata_base=metadata_base,
        )

        if result["inserted_count"] == 0:
            print("[RAG] No new chunks to process")
        else:
            print(
                f"[RAG] Incremental indexing completed - "
                f"{result['inserted_count']} chunks processed"
            )
        return result

    # ===== Online Pipeline =====

    async def retrieve(
        self,
        query: str,
        source: str = "both",
        top_k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Unified query interface delegated to the retrieval layer.
        """
        return await self.retriever.retrieve(
            query=query,
            source=source,
            top_k=top_k,
            filters=filters,
        )

    # ===== Convenience Methods =====

    async def research(
        self,
        query: str,
        include_history: bool = True,
    ) -> str:
        """High-level research interface used by the Librarian."""
        source = "both" if include_history else "kb"

        results = await self.retrieve(query=query, source=source)

        formatted = self._format_research_results(
            query=query,
            results=results,
        )

        return formatted

    def _format_research_results(self, query: str, results: Dict[str, Any]) -> str:
        """Format RAG results into a readable research report."""

        report = f"""
        === RAG Research Results for: "{query}" ===

        Knowledge Base Results:
        """
        for i, kb_result in enumerate(results["kb_results"], 1):
            report += f"""{i}. Source: {kb_result['doc_name']}
                            Similarity: {kb_result['similarity']:.2f}
                            Text: {kb_result['chunk_text'][:200]}...
                        """

        if results["findings_results"]:
            report += "\n\nHistorical Findings:\n"
            for i, finding in enumerate(results["findings_results"], 1):
                report += f"""
                            {i}. {finding['title']} ({finding['severity']})
                            Target: {finding['target_ip']}
                            Similarity: {finding['similarity']:.2f}
                            """

        return report

    # ===== Lifecycle Management =====

    async def health_check(self) -> Dict[str, Any]:
        try:
            test_embedding = await self.embedding_client.embed_text("test")
            embedding_ok = len(test_embedding) == 1024

            from src.database import manager

            db_ok = manager.test_connection() is not None

            return {
                "status": "healthy" if (embedding_ok and db_ok) else "unhealthy",
                "embedding_client": "ok" if embedding_ok else "failed",
                "database": "ok" if db_ok else "failed",
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
