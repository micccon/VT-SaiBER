from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Iterable, Optional

from src.config import RuntimeConfig
from src.state.cyber_state import CyberState
from src.state.models import AgentError, AgentLogEntry
from src.skills.skills import Skill
from src.utils.agent_runtime import BaseToolPolicy, run_chat_completion, run_tool_worker, try_resolve_openrouter_runtime


class BaseAgent(ABC):
    """Shared lifecycle helpers for all specialist agents."""

    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.skills: list[Skill] = []
        self._client = None
        self._model = ""
        self._client_error: str | None = None

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        pass

    @abstractmethod
    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        pass

    def register_skill(self, skill: Skill) -> None:
        self.skills.append(skill)

    def _render_skills_for_state(self, state: CyberState) -> str:
        chunks = [skill.render() for skill in self.skills]
        return "\n\n".join(chunks) if chunks else ""

    def _init_runtime(
        self,
        *,
        config: RuntimeConfig,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        runtime, self._client_error = try_resolve_openrouter_runtime(
            config=config,
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
        )
        if runtime is not None:
            self._client = runtime.client
            self._model = runtime.model

    def _agent_update(self, state: CyberState, **updates: Any) -> Dict[str, Any]:
        return {"current_agent": self.name, "iteration_count": int(state.get("iteration_count", 0)) + 1, **updates}

    def _error_update(
        self,
        state: CyberState,
        *,
        error_type: str,
        message: str,
        recoverable: bool = True,
        **updates: Any,
    ) -> Dict[str, Any]:
        return self._agent_update(state, **updates, **self.log_error(state, error_type=error_type, error=message, recoverable=recoverable))

    def _llm_unavailable_update(
        self,
        state: CyberState,
        *,
        message: str | None = None,
        **updates: Any,
    ) -> Dict[str, Any]:
        return self._error_update(state, error_type="LLMConfigError", message=message or self._client_error or "OPENROUTER_API_KEY is not configured.", recoverable=False, **updates)

    async def _run_chat_agent(
        self,
        state: CyberState,
        *,
        user_prompt: str,
        history: Iterable[dict[str, Any]] | None = None,
        temperature: float = 0.0,
        error_message: str = "LLM chat completion failed.",
    ) -> str | Dict[str, Any]:
        if self._client is None:
            return self._llm_unavailable_update(state)
        try:
            return await run_chat_completion(client=self._client, model=self._model, system_prompt=self.system_prompt, user_prompt=user_prompt, history=history, temperature=temperature)
        except Exception as exc:
            return self._error_update(state, error_type="LLMError", message=f"{error_message} {exc}", recoverable=False)

    async def _run_tool_agent(
        self,
        state: CyberState,
        *,
        user_prompt: str,
        allowed_tools: Iterable[str],
        extractor: Callable[[list[dict[str, Any]], CyberState], Dict[str, Any]],
        required_tools: Iterable[str] | None = None,
        policy: BaseToolPolicy | None = None,
        max_rounds: int = 8,
        error_message: str = "LLM/tool loop failed.",
    ) -> Dict[str, Any]:
        if self._client is None:
            return self._llm_unavailable_update(state)
        try:
            result = await run_tool_worker(client=self._client, model=self._model, system_prompt=self.system_prompt, user_prompt=user_prompt, allowed_tools=allowed_tools, required_tools=required_tools, policy=policy, max_rounds=max_rounds)
            return extractor(result.messages, state)
        except Exception as exc:
            return self._error_update(state, error_type="LLMError", message=f"{error_message} {exc}", recoverable=False)

    def log_action(
        self,
        state: CyberState,
        action: str,
        target: Optional[str] = None,
        findings: Optional[Dict[str, Any]] = None,
        decision: Optional[str] = None,
        reasoning: Optional[str] = None,
    ) -> Dict[str, Any]:
        entry = AgentLogEntry(agent=self.name, action=action, target=target, findings=findings, decision=decision, reasoning=reasoning)
        return {"agent_log": [entry]}

    def log_error(
        self,
        state: CyberState,
        error_type: str,
        error: str,
        recoverable: bool = True,
    ) -> Dict[str, Any]:
        err = AgentError(agent=self.name, error_type=error_type, error=error, recoverable=recoverable)
        return {"errors": [err]}
