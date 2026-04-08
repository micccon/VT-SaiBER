"""
Ingest curated tool manuals into the RAG knowledge_base table.

Walks manuals_curated/, chunks each file (markdown chunker for .md, simple
chunker for .txt/.pdf), embeds with the local BGE model, and inserts into
Postgres + pgvector via rag_manager.

Usage:
    python scripts/ingest_manuals.py
    python scripts/ingest_manuals.py --src manuals_curated --reset
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from src.database.rag.embedding import EmbeddingClient
from src.database.rag.indexing import IndexingPipeline
from src.database.rag.rag_manager import clear_kb_by_source_dir, insert_kb_chunk


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", default="manuals_curated", type=Path)
    parser.add_argument("--max-chars", default=800, type=int)
    parser.add_argument("--overlap", default=100, type=int)
    parser.add_argument("--batch-size", default=32, type=int)
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete previous chunks from this source dir before ingesting.",
    )
    args = parser.parse_args()

    src = args.src.resolve()
    if not src.is_dir():
        raise SystemExit(f"source directory not found: {src}")

    if args.reset:
        deleted = clear_kb_by_source_dir(str(src))
        print(f"Removed {deleted} existing chunks from {src}")

    print(f"Chunking {src} ...")
    pipeline = IndexingPipeline(max_chars=args.max_chars, overlap=args.overlap)
    chunks = await pipeline.process_documents(
        source_paths=[str(src)],
        metadata_base={"corpus": "tool_manuals"},
    )
    print(f"Produced {len(chunks)} chunks.")

    if not chunks:
        return

    print(f"Embedding with batch_size={args.batch_size} ...")
    client = EmbeddingClient(batch_size=args.batch_size)
    texts = [chunk.chunk_text for chunk in chunks]
    embeddings = await client.embed_texts(texts)

    print("Inserting into knowledge_base ...")
    for chunk, embedding in zip(chunks, embeddings):
        chunk.embedding = embedding
        insert_kb_chunk(chunk)

    per_tool: dict[str, int] = {}
    for chunk in chunks:
        tool = chunk.metadata.get("tool", "unknown")
        per_tool[tool] = per_tool.get(tool, 0) + 1

    print(f"\nInserted {len(chunks)} chunks.")
    print("Per tool:")
    for tool, count in sorted(per_tool.items(), key=lambda kv: -kv[1]):
        print(f"  {tool:15s} {count}")


if __name__ == "__main__":
    asyncio.run(main())
