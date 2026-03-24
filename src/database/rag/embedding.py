"""
Embedding Client Module
Use local SentenceTransformer with BAAI/bge-large-en-v1.5 for RAG embeddings.
"""

# src/database/rag/embedding.py

from typing import List
import asyncio

from sentence_transformers import SentenceTransformer


EMBEDDING_MODEL = "BAAI/bge-large-en-v1.5"
EMBEDDING_DIM = 1024  # bge-large-en-v1.5 output dimension


class EmbeddingClient:
    def __init__(self):
        # Load model once at startup; this may take some time the first run
        self.model = SentenceTransformer(EMBEDDING_MODEL)

    async def embed_text(self, text: str) -> List[float]:
        return (await self.embed_texts([text]))[0]

    async def embed_texts(self, texts: List[str]) -> List[List[float]]:
        """
        Async wrapper around SentenceTransformer.encode.
        Normalizes embeddings as recommended for BGE models.
        """
        def _encode_batch() -> List[List[float]]:
            emb = self.model.encode(
                texts,
                normalize_embeddings=True,   # cosine similarity works better
                convert_to_numpy=True,
            )
            return emb.tolist()  # numpy array -> nested Python list

        return await asyncio.to_thread(_encode_batch)