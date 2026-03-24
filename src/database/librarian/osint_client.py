from __future__ import annotations

from typing import Any, Dict, List, Optional

from tavily import AsyncTavilyClient  # pip install tavily-python
from src.config import get_runtime_config


class OSINTClient:
    """Thin wrapper around Tavily (or其他 OSINT) for Librarian."""

    def __init__(self, api_key: Optional[str] = None, max_results: Optional[int] = None):
        cfg = get_runtime_config()
        key = api_key or cfg.tavily_api_key
        self._client: Optional[AsyncTavilyClient] = (
            AsyncTavilyClient(api_key=key) if key else None
        )
        self._max_results = max_results or getattr(cfg, "tavily_max_results", 5)

    async def search(self, query: str) -> List[Dict[str, Any]]:
        """Return normalized OSINT results list."""
        if self._client is None:
            return []

        try:
            resp = await self._client.search(
                query=query,
                max_results=self._max_results,
                include_answer=False,
            )
            return resp.get("results", [])
        except Exception:
            return []