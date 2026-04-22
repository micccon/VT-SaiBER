"""
Embedding Client Module
Use local SentenceTransformer with BAAI/bge-large-en-v1.5 for RAG embeddings.
"""

# src/database/rag/embedding.py

from typing import List
import asyncio
from functools import lru_cache

from sentence_transformers import SentenceTransformer


EMBEDDING_MODEL = "BAAI/bge-large-en-v1.5"
EMBEDDING_DIM = 1024  # bge-large-en-v1.5 output dimension
DEFAULT_BATCH_SIZE = 32


class EmbeddingClient:
    def __init__(self, batch_size: int = DEFAULT_BATCH_SIZE):
        self.model = self._load_model()
        self.batch_size = batch_size

    @staticmethod
    @lru_cache(maxsize=1)
    def _load_model() -> SentenceTransformer:
        return SentenceTransformer(EMBEDDING_MODEL)

    async def embed_text(self, text: str) -> List[float]:
        return (await self.embed_texts([text]))[0]

    def embed_text_sync(self, text: str) -> List[float]:
        return self.embed_texts_sync([text])[0]

    async def embed_texts(
        self,
        texts: List[str],
        batch_size: int | None = None,
    ) -> List[List[float]]:
        """
        Async wrapper around SentenceTransformer.encode.
        Internally batches to bound peak memory on large inputs.
        Normalized embeddings (cosine similarity).
        """
        if not texts:
            return []

        effective_batch = batch_size or self.batch_size

        def _encode_all() -> List[List[float]]:
            return self.embed_texts_sync(texts, batch_size=effective_batch)

        return await asyncio.to_thread(_encode_all)

    def embed_texts_sync(
        self,
        texts: List[str],
        batch_size: int | None = None,
    ) -> List[List[float]]:
        if not texts:
            return []

        effective_batch = batch_size or self.batch_size
        results: List[List[float]] = []
        for start in range(0, len(texts), effective_batch):
            batch = texts[start:start + effective_batch]
            emb = self.model.encode(
                batch,
                normalize_embeddings=True,
                convert_to_numpy=True,
                show_progress_bar=False,
            )
            results.extend(emb.tolist())
        return results
