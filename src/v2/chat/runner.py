"""Tool-less chat/synthesis runner for the v2 architecture."""

from __future__ import annotations

from typing import Any, Iterable

from pydantic import TypeAdapter

from src.utils.agent_runtime.client import create_chat_completion_with_retry, resolve_openrouter_runtime
from src.utils.parsers import extract_json_payload
from src.v2.contracts.chat import ChatSynthesisResult, ChatSynthesisSpec


def _extract_content_text(content: Any) -> str:
    """Flatten SDK content blocks into plain text when possible."""

    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if isinstance(item, dict):
                text = item.get("text")
                if text:
                    parts.append(str(text))
                continue
            text = getattr(item, "text", None)
            if text:
                parts.append(str(text))
        return "\n".join(part for part in parts if part).strip()
    if isinstance(content, dict):
        text = content.get("text")
        return str(text) if text else ""
    text = getattr(content, "text", None)
    return str(text) if text else ""


def _extract_response_text(response: Any) -> str:
    """Read assistant text from an OpenAI-compatible chat response."""

    choices = getattr(response, "choices", None) or []
    if not choices:
        return ""
    message = getattr(choices[0], "message", None)
    if message is None and isinstance(choices[0], dict):
        message = choices[0].get("message")
    if isinstance(message, dict):
        return _extract_content_text(message.get("content"))
    return _extract_content_text(getattr(message, "content", None))


class V2ChatSynthesisRunner:
    """Run a structured non-tool agent over the shared OpenRouter chat path."""

    def __init__(
        self,
        *,
        client: Any | None = None,
        model: str | None = None,
    ):
        self._client = client
        self._model = model

    async def run(
        self,
        spec: ChatSynthesisSpec[Any],
        *,
        user_input: str,
        history: Iterable[dict[str, Any]] | None = None,
    ) -> ChatSynthesisResult[Any]:
        """Execute one chat/synthesis run and return a typed outcome."""

        client = self._client
        model = self._model or spec.model.model

        if client is None:
            runtime = resolve_openrouter_runtime(
                model=spec.model.model,
                api_key=spec.model.api_key,
                base_url=spec.model.base_url,
                timeout_seconds=spec.model.timeout_seconds,
            )
            client = runtime.client
            model = runtime.model

        if hasattr(client, "chat") and getattr(client.chat, "completions", None) is not None:
            response = await create_chat_completion_with_retry(
                client=client,
                model=model,
                purpose="v2_chat_synthesis",
                messages=[
                    {"role": "system", "content": spec.instructions},
                    *(list(history or [])),
                    {"role": "user", "content": user_input},
                ],
                temperature=spec.model.temperature,
            )
            raw_text = _extract_response_text(response)
            raw_result = response
        elif hasattr(client, "ainvoke"):
            response = await client.ainvoke(user_input)
            if isinstance(response, dict):
                raw_text = str(response.get("content") or "")
            else:
                raw_text = str(getattr(response, "content", response))
            raw_result = response
        else:
            raise RuntimeError("Synthesis client does not support chat completions or ainvoke")

        payload = extract_json_payload(raw_text)
        outcome = TypeAdapter(spec.output_type).validate_python(payload)
        return ChatSynthesisResult(outcome=outcome, raw_result=raw_result, raw_text=raw_text)
