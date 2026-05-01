from __future__ import annotations

import asyncio
import inspect
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from src.runtime import chat as runner_mod
from src.runtime.contracts import ChatSynthesisSpec, ModelConfig


class _SampleOutcome(BaseModel):
    status: str
    summary: str = ""


class _FakeCompletions:
    def __init__(self, response):
        self._response = response

    async def create(self, **kwargs):
        return self._response


class _FakeChat:
    def __init__(self, response):
        self.completions = _FakeCompletions(response)


class _FakeClient:
    def __init__(self, response):
        self.chat = _FakeChat(response)


class _FakeInvokeClient:
    async def ainvoke(self, user_prompt: str):
        return {"content": '{"status":"ok","summary":"ainvoke"}'}


def _spec() -> ChatSynthesisSpec[_SampleOutcome]:
    return ChatSynthesisSpec(
        agent_name="demo",
        instructions="Return JSON",
        model=ModelConfig(
            model="test-model",
            api_key="test-key",
            base_url="https://example.invalid",
        ),
        output_type=_SampleOutcome,
    )


def _run(coro):
    return asyncio.run(coro)


def test_chat_synthesis_runner_uses_core_llm_client():
    source = inspect.getsource(runner_mod)
    assert "src.core.llm_client" in source
    assert "src.chat" not in source


def test_chat_synthesis_runner_parses_structured_output():
    response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content='{"status":"ok","summary":"done"}')
            )
        ]
    )

    result = _run(
        runner_mod.ChatSynthesisRunner(client=_FakeClient(response)).run(
            _spec(),
            user_input="hello",
        )
    )

    assert result.outcome.status == "ok"
    assert result.outcome.summary == "done"
    assert result.raw_text == '{"status":"ok","summary":"done"}'


def test_chat_synthesis_runner_uses_runtime_configured_client_when_not_injected(monkeypatch):
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='{"status":"ok"}'))]
    )
    captured: dict[str, object] = {}

    def fake_resolve_openrouter_runtime(**kwargs):
        captured["resolve_kwargs"] = dict(kwargs)
        return SimpleNamespace(client=_FakeClient(response), model="resolved-model")

    async def fake_create_chat_completion_with_retry(**kwargs):
        captured["completion_kwargs"] = dict(kwargs)
        return response

    monkeypatch.setattr(runner_mod, "resolve_openrouter_runtime", fake_resolve_openrouter_runtime)
    monkeypatch.setattr(runner_mod, "create_chat_completion_with_retry", fake_create_chat_completion_with_retry)

    result = _run(runner_mod.ChatSynthesisRunner().run(_spec(), user_input="hello"))

    assert result.outcome.status == "ok"
    assert captured["resolve_kwargs"]["model"] == "test-model"
    assert captured["completion_kwargs"]["model"] == "resolved-model"


def test_chat_synthesis_runner_supports_ainvoke_clients():
    result = _run(
        runner_mod.ChatSynthesisRunner(client=_FakeInvokeClient()).run(
            _spec(),
            user_input="hello",
        )
    )

    assert result.outcome.status == "ok"
    assert result.outcome.summary == "ainvoke"


def test_chat_synthesis_runner_raises_for_unsupported_client():
    with pytest.raises(RuntimeError):
        _run(runner_mod.ChatSynthesisRunner(client=object()).run(_spec(), user_input="hello"))
