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

    async def retrieve_from_kb(
        self,
        query: str,
        top_k: int = 5,
        filters: Dict[str, Any] | None = None,
    ) -> List[Dict[str, Any]]:
        query_emb = await self.embedding_client.embed_text(query)
        rows = search_by_embedding(query_emb, top_k=top_k, filters=filters)
        return rows