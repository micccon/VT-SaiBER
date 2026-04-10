"""
Online Retrieval Module
Query knowledge_base and findings_embeddings via vector similarity search.
Returns formatted results with metadata and similarity scores.
"""

# src/database/rag/retriever.py

from typing import Any, Dict, List

from .embedding import EmbeddingClient
from .rag_manager import search_by_embedding


class RAGRetriever:
    def __init__(self, embedding_client: EmbeddingClient):
        self.embedding_client = embedding_client

    async def retrieve(
        self,
        query: str,
        source: str = "both",
        top_k: int = 5,
        filters: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Unified retrieval across the knowledge base and historical findings."""
        results: Dict[str, Any] = {}

        if source in ["kb", "both"]:
            results["kb_results"] = await self.retrieve_from_kb(
                query=query,
                top_k=top_k,
                filters=filters,
            )
        else:
            results["kb_results"] = []

        if source in ["findings", "both"]:
            results["findings_results"] = await self.retrieve_from_findings(
                query=query,
                top_k=top_k,
                filters=filters,
            )
        else:
            results["findings_results"] = []

        results["combined"] = results["kb_results"] + results["findings_results"]
        return results

    async def retrieve_from_kb(
        self,
        query: str,
        top_k: int = 5,
        filters: Dict[str, Any] | None = None,
    ) -> List[Dict[str, Any]]:
        query_emb = await self.embedding_client.embed_text(query)
        rows = search_by_embedding(query_emb, top_k=top_k, filters=filters)
        return rows

    async def retrieve_from_findings(
        self,
        query: str,
        top_k: int = 5,
        filters: Dict[str, Any] | None = None,
    ) -> List[Dict[str, Any]]:
        """
        Historical findings retrieval via the findings_embeddings table.

        Filters are not yet applied because findings metadata querying lives in
        the main database manager layer and needs a stable contract first.
        """
        from src.database.manager import search_similar_findings

        query_emb = await self.embedding_client.embed_text(query)
        rows = search_similar_findings(
            embedding_vector=query_emb,
            limit=top_k,
            threshold=0.0,
        )
        return rows
