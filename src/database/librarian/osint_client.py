from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from tavily import AsyncTavilyClient  # type: ignore[import-not-found]
except Exception:
    AsyncTavilyClient = None  # type: ignore[assignment]
from src.config import get_runtime_config


class OSINTClient:
    """Thin wrapper around Tavily (or other OSINT) for Librarian and other agents."""

    def __init__(self, api_key: Optional[str] = None, max_results: Optional[int] = None):
        cfg = get_runtime_config()
        self._api_key = api_key or getattr(cfg, "tavily_api_key", None)
        self._client: Optional[Any] = None
        self._max_results = max_results or getattr(cfg, "tavily_max_results", 5)

    def is_configured(self) -> bool:
        return bool(self._api_key and AsyncTavilyClient is not None)

    def _ensure_client(self) -> Optional[Any]:
        if self._client is not None:
            return self._client
        if not self.is_configured():
            return None
        self._client = AsyncTavilyClient(api_key=self._api_key)
        return self._client

    async def search(self, query: str, *, max_results: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return normalized OSINT results list."""
        client = self._ensure_client()
        if client is None:
            return []

        try:
            resp = await client.search(
                query=query,
                max_results=max_results or self._max_results,
                include_answer=False,
            )
            raw_results = resp.get("results", []) or []
        except Exception:
            return []

        normalized: List[Dict[str, Any]] = []
        for item in raw_results:
            if not isinstance(item, dict):
                continue
            normalized.append(
                {
                    "source": "tavily",
                    "title": item.get("title") or "",
                    "url": item.get("url") or "",
                    "snippet": item.get("content") or item.get("snippet") or "",
                    "score": item.get("score"),
                    "raw": item,
                }
            )
        return normalized
