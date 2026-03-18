"""
Minimal OpenRouter chat-completions client with reasoning_details continuity.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests


class OpenRouterError(RuntimeError):
    """Raised when OpenRouter request/response handling fails."""


@dataclass
class OpenRouterMessage:
    content: str
    reasoning_details: Any = None
    raw: Optional[Dict[str, Any]] = None


class OpenRouterClient:
    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "https://openrouter.ai/api/v1",
        timeout_seconds: int = 90,
    ):
        if not api_key:
            raise OpenRouterError("OPENROUTER_API_KEY is required")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        *,
        temperature: float = 0.0,
        reasoning_enabled: bool = True,
        extra_payload: Optional[Dict[str, Any]] = None,
    ) -> OpenRouterMessage:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "reasoning": {"enabled": reasoning_enabled},
        }
        if extra_payload:
            payload.update(extra_payload)

        data = await asyncio.to_thread(self._post_json, payload)
        try:
            message = data["choices"][0]["message"]
        except Exception as exc:
            raise OpenRouterError(f"Unexpected OpenRouter response shape: {data}") from exc

        return OpenRouterMessage(
            content=message.get("content", "") or "",
            reasoning_details=message.get("reasoning_details"),
            raw=data,
        )

    def _post_json(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        response = requests.post(
            url=f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            data=json.dumps(payload),
            timeout=self.timeout_seconds,
        )

        if response.status_code >= 400:
            raise OpenRouterError(f"OpenRouter HTTP {response.status_code}: {response.text[:500]}")

        try:
            body = response.json()
        except Exception as exc:
            raise OpenRouterError("OpenRouter returned non-JSON response") from exc

        if "error" in body:
            raise OpenRouterError(f"OpenRouter API error: {body['error']}")
        return body
