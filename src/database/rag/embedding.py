"""
Embedding client abstraction for VT-SaiBER RAG.

Supports OpenRouter-hosted embeddings as the default runtime path and keeps
local SentenceTransformer support available as an explicit fallback mode.
"""

from __future__ import annotations

import asyncio
from functools import lru_cache
from typing import Any, Dict, List

from src.config import RuntimeConfig, get_runtime_config

try:
    from openai import AsyncOpenAI, OpenAI
except Exception:
    AsyncOpenAI = None  # type: ignore[assignment]
    OpenAI = None  # type: ignore[assignment]

try:
    from sentence_transformers import SentenceTransformer
except Exception:
    SentenceTransformer = None  # type: ignore[assignment]


DEFAULT_LOCAL_MODEL = "BAAI/bge-large-en-v1.5"
DEFAULT_OPENROUTER_MODEL = "openai/text-embedding-3-small"
DEFAULT_BATCH_SIZE = 32


class EmbeddingClient:
    def __init__(
        self,
        batch_size: int = DEFAULT_BATCH_SIZE,
        *,
        config: RuntimeConfig | None = None,
    ):
        """Resolve embedding provider/model settings without initializing clients yet."""

        self.config = config or get_runtime_config()
        self.batch_size = batch_size
        self.provider = str(self.config.embedding_provider or "openrouter").strip().lower()
        self.model_name = str(
            self.config.embedding_model
            or (DEFAULT_OPENROUTER_MODEL if self.provider == "openrouter" else DEFAULT_LOCAL_MODEL)
        ).strip()
        if not self.model_name:
            self.model_name = DEFAULT_OPENROUTER_MODEL if self.provider == "openrouter" else DEFAULT_LOCAL_MODEL
        self.dimensions = int(self.config.embedding_dimensions or 1024)
        self.timeout_seconds = int(self.config.embedding_timeout_seconds or 60)
        self._async_client: Any | None = None
        self._sync_client: Any | None = None
        self._local_model: Any | None = None

    def is_available(self) -> bool:
        """Return whether the configured provider can be used in this process."""

        if self.provider == "disabled":
            return False
        if self.provider == "openrouter":
            return bool(
                AsyncOpenAI is not None
                and OpenAI is not None
                and str(self.config.openrouter_api_key or "").strip()
            )
        if self.provider == "local":
            return SentenceTransformer is not None
        return False

    def metadata(self) -> Dict[str, Any]:
        """Return embedding provenance fields to persist beside indexed chunks."""

        return {
            "embedding_provider": self.provider,
            "embedding_model": self.model_name,
            "embedding_dimensions": self.dimensions,
            "embedding_provenance": self.provenance_tag(),
        }

    def provenance_tag(self) -> str:
        """Build the compact provider/model/dimension tag used for reindex checks."""

        return f"{self.provider}:{self.model_name}:{self.dimensions}"

    async def embed_text(self, text: str) -> List[float]:
        """Embed one text string using the configured provider."""

        results = await self.embed_texts([text])
        return results[0] if results else []

    def embed_text_sync(self, text: str) -> List[float]:
        """Synchronously embed one text string for persistence hot paths."""

        results = self.embed_texts_sync([text])
        return results[0] if results else []

    async def embed_texts(
        self,
        texts: List[str],
        batch_size: int | None = None,
    ) -> List[List[float]]:
        """Embed a batch asynchronously, delegating local work to a thread."""

        if not texts:
            return []
        if self.provider == "openrouter":
            return await self._embed_openrouter(texts, batch_size=batch_size)
        if self.provider == "local":
            effective_batch = batch_size or self.batch_size
            return await asyncio.to_thread(self.embed_texts_sync, texts, effective_batch)
        raise RuntimeError(f"Embedding provider '{self.provider}' is unavailable")

    def embed_texts_sync(
        self,
        texts: List[str],
        batch_size: int | None = None,
    ) -> List[List[float]]:
        """Embed a batch synchronously for code paths that cannot await."""

        if not texts:
            return []
        if self.provider == "openrouter":
            return self._embed_openrouter_sync(texts)
        if self.provider == "local":
            model = self._get_local_model()
            effective_batch = batch_size or self.batch_size
            results: List[List[float]] = []
            for start in range(0, len(texts), effective_batch):
                batch = texts[start:start + effective_batch]
                emb = model.encode(
                    batch,
                    normalize_embeddings=True,
                    convert_to_numpy=True,
                    show_progress_bar=False,
                )
                results.extend(emb.tolist())
            return results
        raise RuntimeError(f"Embedding provider '{self.provider}' is unavailable")

    async def _embed_openrouter(
        self,
        texts: List[str],
        *,
        batch_size: int | None = None,
    ) -> List[List[float]]:
        """Call OpenRouter/OpenAI-compatible embeddings in bounded batches."""

        client = self._get_async_openrouter_client()
        effective_batch = batch_size or self.batch_size
        results: List[List[float]] = []
        for start in range(0, len(texts), effective_batch):
            batch = texts[start:start + effective_batch]
            response = await client.embeddings.create(
                model=self.model_name,
                input=batch,
                encoding_format="float",
                dimensions=self.dimensions,
            )
            results.extend([list(item.embedding) for item in response.data])
        return results

    def _embed_openrouter_sync(self, texts: List[str]) -> List[List[float]]:
        """Call the synchronous OpenRouter/OpenAI-compatible embeddings endpoint."""

        client = self._get_sync_openrouter_client()
        response = client.embeddings.create(
            model=self.model_name,
            input=texts,
            encoding_format="float",
            dimensions=self.dimensions,
        )
        return [list(item.embedding) for item in response.data]

    def _get_async_openrouter_client(self):
        """Lazily create the async OpenRouter client after config is known."""

        if self._async_client is not None:
            return self._async_client
        if AsyncOpenAI is None:
            raise RuntimeError("openai is not installed")
        api_key = str(self.config.openrouter_api_key or "").strip()
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY is required for hosted embeddings")
        self._async_client = AsyncOpenAI(
            api_key=api_key,
            base_url=self.config.openrouter_base_url,
            timeout=self.timeout_seconds,
        )
        return self._async_client

    def _get_sync_openrouter_client(self):
        """Lazily create the sync OpenRouter client for persistence/indexing."""

        if self._sync_client is not None:
            return self._sync_client
        if OpenAI is None:
            raise RuntimeError("openai is not installed")
        api_key = str(self.config.openrouter_api_key or "").strip()
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY is required for hosted embeddings")
        self._sync_client = OpenAI(
            api_key=api_key,
            base_url=self.config.openrouter_base_url,
            timeout=self.timeout_seconds,
        )
        return self._sync_client

    def _get_local_model(self):
        """Lazily load the local model only when explicitly configured."""

        if self._local_model is not None:
            return self._local_model
        self._local_model = self._load_local_model(self.model_name)
        return self._local_model

    @staticmethod
    @lru_cache(maxsize=4)
    def _load_local_model(model_name: str) -> Any:
        """Load and cache local SentenceTransformer models by model name."""

        if SentenceTransformer is None:
            raise RuntimeError("sentence-transformers is not installed")
        return SentenceTransformer(model_name)
