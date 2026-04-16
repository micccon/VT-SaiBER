# src/database/rag/rag_engine.py

"""
RAG Orchestrator Module
Main entry point coordinating all RAG sub-modules (embedding, indexing, retrieval).
Provides high-level API for agents and CLI tools.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Optional, Dict, Any, List

from dotenv import load_dotenv

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

    async def index_sources(
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
        result = await indexing_pipeline.index_sources_into_knowledge_base(
            source_paths=resolved_sources,
            embedding_client=self.embedding_client,
            reset=reset,
            batch_size=batch_size,
            metadata_base=base_metadata,
        )
        return result.to_dict()

    # ===== Offline Pipeline =====

    async def rebuild_knowledge_base(
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
        result = await self.index_sources(
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

    async def sync_knowledge_base_incrementally(
        self,
        source_dirs: Optional[List[str]] = None,
        *,
        max_chars: int = 800,
        overlap: int = 100,
        batch_size: Optional[int] = None,
        metadata_base: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Incrementally sync the KB with the current source files.

        New files are indexed, changed files are re-indexed, and removed files
        are deleted from the knowledge_base table.
        """
        print("[RAG] Starting incremental knowledge base indexing...")
        resolved_sources = source_dirs or [DEFAULT_KB_SOURCE_DIR]
        base_metadata = dict(metadata_base or {})
        base_metadata.setdefault("corpus", "testbed_docs")

        indexing_pipeline = IndexingPipeline(
            max_chars=max_chars,
            overlap=overlap,
            )
        result = await indexing_pipeline.sync_sources_into_knowledge_base_incrementally(
            source_paths=resolved_sources,
            embedding_client=self.embedding_client,
            batch_size=batch_size,
            metadata_base=base_metadata,
        )
        result_dict = result.to_dict()

        if result_dict["inserted_count"] == 0:
            print("[RAG] No new chunks to process")
        else:
            print(
                f"[RAG] Incremental indexing completed - "
                f"{result_dict['inserted_count']} chunks processed"
            )
        return result_dict

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
        """Compatibility wrapper for the old generic ingestion name."""
        return await self.index_sources(
            source_dirs=source_dirs,
            reset=reset,
            max_chars=max_chars,
            overlap=overlap,
            batch_size=batch_size,
            metadata_base=metadata_base,
        )

    async def index_knowledge_base_full(
        self,
        source_dirs: Optional[List[str]] = None,
        *,
        max_chars: int = 800,
        overlap: int = 100,
        batch_size: Optional[int] = None,
        metadata_base: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compatibility wrapper for the old full indexing name."""
        return await self.rebuild_knowledge_base(
            source_dirs=source_dirs,
            max_chars=max_chars,
            overlap=overlap,
            batch_size=batch_size,
            metadata_base=metadata_base,
        )

    async def index_knowledge_base_incremental(
        self,
        source_dirs: Optional[List[str]] = None,
        *,
        max_chars: int = 800,
        overlap: int = 100,
        batch_size: Optional[int] = None,
        metadata_base: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compatibility wrapper for the old incremental indexing name."""
        return await self.sync_knowledge_base_incrementally(
            source_dirs=source_dirs,
            max_chars=max_chars,
            overlap=overlap,
            batch_size=batch_size,
            metadata_base=metadata_base,
        )

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


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VT-SaiBER RAG knowledge-base maintenance")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_shared_args(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument(
            "--source-dir",
            action="append",
            dest="source_dirs",
            default=[],
            help=(
                "Source directory or file to index. Repeatable. "
                f"Defaults to {DEFAULT_KB_SOURCE_DIR}."
            ),
        )
        subparser.add_argument("--max-chars", type=int, default=800)
        subparser.add_argument("--overlap", type=int, default=100)
        subparser.add_argument("--batch-size", type=int, default=None)
        subparser.add_argument(
            "--metadata",
            action="append",
            default=[],
            help="Chunk metadata in KEY=VALUE format. Repeatable.",
        )

    rebuild = subparsers.add_parser("rebuild", help="Clear and rebuild the knowledge base")
    add_shared_args(rebuild)

    sync = subparsers.add_parser("sync", help="Incrementally sync the knowledge base")
    add_shared_args(sync)

    index = subparsers.add_parser("index", help="Index source files without clearing the full KB")
    add_shared_args(index)
    index.add_argument(
        "--reset",
        action="store_true",
        help="Delete rows for the selected sources before indexing them.",
    )

    return parser


def _parse_metadata_pairs(pairs: List[str]) -> Dict[str, str]:
    metadata: Dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key.strip():
            raise ValueError(f"Invalid metadata pair '{pair}'. Expected KEY=VALUE format.")
        metadata[key.strip()] = value.strip()
    return metadata


async def _run_cli(args: argparse.Namespace) -> Dict[str, Any]:
    rag = RAGOrchestrator()
    source_dirs = args.source_dirs or [DEFAULT_KB_SOURCE_DIR]
    metadata_base = _parse_metadata_pairs(args.metadata)

    common_kwargs = {
        "source_dirs": source_dirs,
        "max_chars": args.max_chars,
        "overlap": args.overlap,
        "batch_size": args.batch_size,
        "metadata_base": metadata_base,
    }

    if args.command == "rebuild":
        return await rag.rebuild_knowledge_base(**common_kwargs)
    if args.command == "sync":
        return await rag.sync_knowledge_base_incrementally(**common_kwargs)
    if args.command == "index":
        return await rag.index_sources(reset=args.reset, **common_kwargs)

    raise ValueError(f"Unsupported command: {args.command}")


def main() -> int:
    load_dotenv()
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        result = asyncio.run(_run_cli(args))
    except Exception as exc:
        print(f"[RAG] Command failed: {exc}")
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())