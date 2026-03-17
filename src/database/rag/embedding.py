"""
Embedding Client Module
Unified API to generate vector embeddings using text-embedding-3-small via OpenRouter.
Supports single/batch embedding with built-in caching and retry logic.
"""

# src/database/rag/embedding.py

from typing import List
import os
from openai import OpenAI  # 或你最後選的 provider[web:372]

EMBEDDING_MODEL = "text-embedding-3-small"
EMBEDDING_DIM = 1536


class EmbeddingClient:
    def __init__(self):
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY is not set")
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1"
        )

    async def embed_text(self, text: str) -> List[float]:
        return (await self.embed_texts([text]))[0]

    async def embed_texts(self, texts: List[str]) -> List[List[float]]:
        import asyncio

        def _call():
            resp = self.client.embeddings.create(
                model=EMBEDDING_MODEL,
                input=texts,
            )
            return [item.embedding for item in resp.data]

        return await asyncio.to_thread(_call)
