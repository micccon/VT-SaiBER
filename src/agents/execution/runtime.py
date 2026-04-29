"""Reusable execution framework built on top of the OpenAI Agents SDK."""

from __future__ import annotations

import importlib
import json
import logging
import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, Mapping

from src.utils.agent_runtime.transcript import extract_message_text, make_assistant_message, make_tool_message
from src.utils.parsers import to_jsonable
from src.utils.tools.loader import normalize_tool_payload, serialize_tool_result
from src.utils.tools.models import RuntimeTool
from src.utils.tools.policy import BaseToolPolicy, ToolInterception

logger = logging.getLogger(__name__)


@dataclass
class MCPServerSpec:
    """Configuration for exposing an MCP server through the Agents SDK."""

    name: str
    url: str
    allowed_tools: set[str] = field(default_factory=set)
    approval_tools: set[str] = field(default_factory=set)
    cache_tools_list: bool = True


@dataclass
class FrameworkRunResult:
    """Normalized result returned by the execution framework."""

    raw_result: Any
    messages: list[dict[str, Any]]
    final_output: Any
    new_items: list[Any] = field(default_factory=list)
    turns: int = 0


def _load_agents_sdk(sdk_module: Any | None = None) -> Any:
    """Load the Agents SDK lazily so the repo still imports when the dependency is absent."""

    if sdk_module is not None:
        return sdk_module
    try:
        return importlib.import_module("agents")
    except Exception as exc:  # pragma: no cover - exercised only when dependency is missing
        raise RuntimeError("openai-agents is not installed") from exc


def _coerce_mapping(value: Any) -> dict[str, Any]:
    """Convert a SDK object into a plain mapping when possible."""

    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "model_dump"):
        try:
            dumped = value.model_dump()
            if isinstance(dumped, dict):
                return dict(dumped)
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_")}
    return {}


def _item_kind(item: Any) -> str:
    """Return a best-effort type label for a run item."""

    if isinstance(item, dict):
        for key in ("type", "kind", "item_type", "name"):
            candidate = item.get(key)
            if candidate:
                return str(candidate)
        return "dict"
    for attr in ("type", "kind", "item_type"):
        candidate = getattr(item, attr, None)
        if candidate:
            return str(candidate)
    return type(item).__name__


def _item_text(item: Any) -> str:
    """Extract the human-readable text from a run item."""

    if isinstance(item, dict):
        for key in ("text", "content", "output", "message", "summary"):
            candidate = item.get(key)
            if candidate:
                return extract_message_text(candidate)
        return ""
    for attr in ("text", "content", "output", "message", "summary"):
        candidate = getattr(item, attr, None)
        if candidate:
            return extract_message_text(candidate)
    return ""


def _tool_call_id(item: Any) -> str:
    """Extract a tool-call identifier from a run item."""

    if isinstance(item, dict):
        for key in ("tool_call_id", "call_id", "id"):
            candidate = item.get(key)
            if candidate:
                return str(candidate)
        return ""
    for attr in ("tool_call_id", "call_id", "id"):
        candidate = getattr(item, attr, None)
        if candidate:
            return str(candidate)
    return ""


def _tool_name(item: Any) -> str:
    """Extract the tool name from a run item."""

    if isinstance(item, dict):
        for key in ("name", "tool_name"):
            candidate = item.get(key)
            if candidate:
                return str(candidate)
        function = item.get("function")
        if isinstance(function, dict):
            candidate = function.get("name")
            if candidate:
                return str(candidate)
        return ""
    for attr in ("name", "tool_name"):
        candidate = getattr(item, attr, None)
        if candidate:
            return str(candidate)
    function = getattr(item, "function", None)
    if function is not None:
        candidate = getattr(function, "name", None)
        if candidate:
            return str(candidate)
    return ""


def _tool_args(item: Any) -> dict[str, Any]:
    """Extract tool-call arguments from a run item."""

    if isinstance(item, dict):
        for key in ("args", "arguments", "input", "parameters"):
            candidate = item.get(key)
            if isinstance(candidate, dict):
                return dict(candidate)
        function = item.get("function")
        if isinstance(function, dict):
            for key in ("arguments", "args", "input"):
                candidate = function.get(key)
                if isinstance(candidate, dict):
                    return dict(candidate)
                if isinstance(candidate, str) and candidate.strip():
                    try:
                        parsed = json.loads(candidate)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(parsed, dict):
                        return parsed
        return {}
    for attr in ("args", "arguments", "input", "parameters"):
        candidate = getattr(item, attr, None)
        if isinstance(candidate, dict):
            return dict(candidate)
        if isinstance(candidate, str) and candidate.strip():
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    function = getattr(item, "function", None)
    if function is not None:
        for attr in ("arguments", "args", "input"):
            candidate = getattr(function, attr, None)
            if isinstance(candidate, dict):
                return dict(candidate)
            if isinstance(candidate, str) and candidate.strip():
                try:
                    parsed = json.loads(candidate)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    return parsed
    return {}


def _tool_payload(item: Any, *, tool_name: str, invocation: dict[str, Any]) -> dict[str, Any]:
    """Extract a normalized payload from a tool result item."""

    raw_payload: Any = None
    if isinstance(item, dict):
        for key in ("structured_content", "structuredContent", "output", "content", "result", "tool_result"):
            candidate = item.get(key)
            if candidate is not None:
                raw_payload = candidate
                break
    else:
        for attr in ("structured_content", "structuredContent", "output", "content", "result", "tool_result"):
            candidate = getattr(item, attr, None)
            if candidate is not None:
                raw_payload = candidate
                break

    normalized = normalize_tool_payload(raw_payload, tool_name=tool_name, invocation=invocation)
    if isinstance(normalized, dict):
        return normalized
    return {
        "status": "success",
        "tool": tool_name,
        "invocation": invocation,
        "result": normalized,
    }


def _normalize_input_item(item: Any) -> dict[str, Any] | None:
    """Normalize one item from `to_input_list()` into the transcript shape."""

    mapping = _coerce_mapping(item)
    role = str(mapping.get("role") or mapping.get("type") or "").lower()
    if role in {"assistant", "tool", "user", "system"}:
        normalized = dict(mapping)
        if role == "assistant":
            normalized["content"] = mapping.get("content", "")
            if "tool_calls" in mapping and isinstance(mapping["tool_calls"], list):
                normalized["tool_calls"] = list(mapping["tool_calls"])
        elif role == "tool":
            tool_name = str(mapping.get("name") or mapping.get("tool_name") or "")
            invocation = mapping.get("invocation") if isinstance(mapping.get("invocation"), dict) else {}
            normalized["content"] = _tool_payload(item, tool_name=tool_name, invocation=invocation)
        return normalized

    if mapping:
        text = _item_text(mapping)
        if text:
            return make_assistant_message(text)
    return None


def _normalize_run_items(items: Iterable[Any], *, final_output: Any | None = None) -> list[dict[str, Any]]:
    """Normalize SDK `new_items` into legacy transcript messages."""

    messages: list[dict[str, Any]] = []
    reasoning_chunks: list[str] = []
    for item in items:
        kind = _item_kind(item).lower()
        if "reason" in kind:
            text = _item_text(item)
            if text:
                reasoning_chunks.append(text)
            continue

        if "approval" in kind and "tool" in kind:
            tool_name = _tool_name(item)
            call_id = _tool_call_id(item) or "approval"
            payload = {
                "status": "aborted",
                "message": _item_text(item) or "Execution blocked pending manual approval.",
                "tool": tool_name or None,
            }
            messages.append(make_tool_message(tool_name or "unknown", call_id, payload))
            continue

        if "tool" in kind and "output" in kind:
            tool_name = _tool_name(item)
            call_id = _tool_call_id(item) or "tool-call"
            invocation = _tool_args(item)
            payload = _tool_payload(item, tool_name=tool_name or "unknown", invocation=invocation)
            messages.append(make_tool_message(tool_name or "unknown", call_id, payload))
            continue

        if "tool" in kind and "call" in kind:
            tool_name = _tool_name(item)
            call_id = _tool_call_id(item) or "tool-call"
            arguments = _tool_args(item)
            messages.append(
                make_assistant_message(
                    _item_text(item),
                    [{"id": call_id, "name": tool_name, "args": arguments}],
                )
            )
            continue

        text = _item_text(item)
        if text:
            if reasoning_chunks:
                text = "\n\n".join([*reasoning_chunks, text]).strip()
                reasoning_chunks.clear()
            messages.append(make_assistant_message(text))

    if reasoning_chunks:
        messages.append(make_assistant_message("\n\n".join(reasoning_chunks)))

    if not messages and final_output is not None:
        text = extract_message_text(final_output)
        if text:
            messages.append(make_assistant_message(text))
        else:
            messages.append(make_assistant_message(json.dumps(to_jsonable(final_output), indent=2, default=str)))

    return messages


def normalize_run_result_messages(run_result: Any) -> list[dict[str, Any]]:
    """Normalize a RunResult into the legacy transcript shape used by existing extractors."""

    to_input_list = getattr(run_result, "to_input_list", None)
    if callable(to_input_list):
        for kwargs in (
            {"mode": "preserve_all"},
            {"mode": "normalized"},
            {},
        ):
            try:
                input_items = to_input_list(**kwargs)
            except TypeError:
                continue
            except Exception:
                continue
            normalized = [item for item in (_normalize_input_item(item) for item in input_items or []) if item is not None]
            if normalized:
                return normalized

    new_items = getattr(run_result, "new_items", None) or []
    return _normalize_run_items(new_items, final_output=getattr(run_result, "final_output", None))


class AgentsExecutionEngine:
    """Build and run an Agents SDK workflow over runtime tools and MCP servers."""

    def __init__(
        self,
        *,
        agent_name: str,
        instructions: str,
        model_name: str,
        api_key: str,
        base_url: str,
        timeout_seconds: int | None = None,
        runtime_tools: Iterable[RuntimeTool] | None = None,
        runtime_tool_loader: Callable[[], Awaitable[Iterable[RuntimeTool]]] | None = None,
        mcp_servers: Iterable[MCPServerSpec] | None = None,
        policy: BaseToolPolicy | None = None,
        max_turns: int = 8,
        temperature: float = 0.0,
        trace_include_sensitive_data: bool = False,
        tool_error_message: str = "Execution blocked pending manual approval.",
    ):
        self.agent_name = agent_name
        self.instructions = instructions
        self.model_name = model_name
        self.api_key = api_key
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self.runtime_tools = list(runtime_tools or [])
        self.runtime_tool_loader = runtime_tool_loader
        self.mcp_servers = list(mcp_servers or [])
        self.policy = policy
        self.max_turns = max_turns
        self.temperature = temperature
        self.trace_include_sensitive_data = trace_include_sensitive_data
        self.tool_error_message = tool_error_message

    async def _resolve_runtime_tools(self) -> list[RuntimeTool]:
        if self.runtime_tool_loader is not None:
            resolved = self.runtime_tool_loader()
            if inspect.isawaitable(resolved):
                resolved = await resolved
            return list(resolved)
        return list(self.runtime_tools)

    def _build_model(self, sdk: Any) -> Any:
        async_openai_cls = getattr(sdk, "AsyncOpenAI", None)
        chat_model_cls = getattr(sdk, "OpenAIChatCompletionsModel", None)
        if async_openai_cls is None or chat_model_cls is None:
            raise RuntimeError("OpenAI Agents SDK model classes are unavailable")

        client_kwargs: dict[str, Any] = {
            "api_key": self.api_key,
            "base_url": self.base_url,
        }
        if self.timeout_seconds is not None:
            client_kwargs["timeout"] = self.timeout_seconds
        client = async_openai_cls(**client_kwargs)
        return chat_model_cls(model=self.model_name, openai_client=client)

    def _build_run_config(self, sdk: Any) -> Any:
        run_config_cls = getattr(sdk, "RunConfig", None)
        model_settings_cls = getattr(sdk, "ModelSettings", None)
        if run_config_cls is None:
            return None

        kwargs: dict[str, Any] = {
            "trace_include_sensitive_data": self.trace_include_sensitive_data,
            "tool_error_formatter": self._format_tool_error,
        }
        if model_settings_cls is not None:
            kwargs["model_settings"] = model_settings_cls(temperature=self.temperature)
        return run_config_cls(**kwargs)

    def _format_tool_error(self, args: Any) -> str | None:
        kind = getattr(args, "kind", None)
        if kind == "approval_rejected":
            return self.tool_error_message
        return None

    def _fill_tool_defaults(self, tool: RuntimeTool, arguments: dict[str, Any]) -> dict[str, Any]:
        merged = dict(tool.defaults or {})
        merged.update(arguments or {})
        return merged

    async def _invoke_runtime_tool(self, tool: RuntimeTool, arguments: dict[str, Any]) -> Any:
        call_arguments = self._fill_tool_defaults(tool, arguments)
        if self.policy is not None:
            intercepted = await self.policy.before_call(tool, dict(call_arguments))
            if isinstance(intercepted, ToolInterception):
                return intercepted.payload

        raw_result = await tool.executor(**call_arguments)
        if self.policy is not None:
            raw_result = await self.policy.after_call(tool, dict(call_arguments), raw_result)
        return raw_result

    def _build_function_tool(self, sdk: Any, tool: RuntimeTool) -> Any:
        function_tool_cls = getattr(sdk, "FunctionTool", None)
        if function_tool_cls is None:
            raise RuntimeError("OpenAI Agents SDK FunctionTool is unavailable")

        async def on_invoke_tool(run_context: Any, args_json: str) -> str:
            arguments = {}
            candidate = str(args_json or "").strip()
            if candidate:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    arguments = parsed
                else:
                    raise ValueError("Tool arguments must decode to an object")
            result = await self._invoke_runtime_tool(tool, arguments)
            normalized = normalize_tool_payload(result, tool_name=tool.name, invocation=arguments)
            return serialize_tool_result(normalized)

        return function_tool_cls(
            name=tool.name,
            description=tool.description or tool.name,
            params_json_schema=tool.input_schema or {"type": "object", "properties": {}},
            on_invoke_tool=on_invoke_tool,
        )

    def _build_mcp_server(self, sdk: Any, spec: MCPServerSpec) -> Any:
        mcp_module = getattr(sdk, "mcp", None)
        if mcp_module is None:
            try:
                mcp_module = importlib.import_module("agents.mcp")
            except Exception as exc:  # pragma: no cover - depends on installed SDK shape
                raise RuntimeError("OpenAI Agents SDK MCP helpers are unavailable") from exc

        server_cls = getattr(mcp_module, "MCPServerStreamableHttp", None)
        static_filter = getattr(mcp_module, "create_static_tool_filter", None)
        if server_cls is None:
            raise RuntimeError("OpenAI Agents SDK MCP server helpers are unavailable")

        kwargs: dict[str, Any] = {
            "name": spec.name,
            "params": {"url": spec.url},
            "cache_tools_list": spec.cache_tools_list,
        }
        if spec.allowed_tools and static_filter is not None:
            kwargs["tool_filter"] = static_filter(allowed_tool_names=sorted(spec.allowed_tools))
        if spec.approval_tools:
            kwargs["require_approval"] = {"always": {"tool_names": sorted(spec.approval_tools)}}
        return server_cls(**kwargs)

    async def run(
        self,
        *,
        user_prompt: str,
        context: Any | None = None,
        sdk_module: Any | None = None,
    ) -> FrameworkRunResult:
        """Execute the configured agent and return the normalized transcript."""

        sdk = _load_agents_sdk(sdk_module)
        runtime_tools = await self._resolve_runtime_tools()
        if not runtime_tools and not self.mcp_servers:
            raise RuntimeError("No runtime tools were available for execution")

        model = self._build_model(sdk)
        tools = [self._build_function_tool(sdk, tool) for tool in runtime_tools]
        mcp_servers = [self._build_mcp_server(sdk, spec) for spec in self.mcp_servers]

        agent_kwargs: dict[str, Any] = {
            "name": self.agent_name,
            "instructions": self.instructions,
            "model": model,
        }
        if tools:
            agent_kwargs["tools"] = tools
        if mcp_servers:
            agent_kwargs["mcp_servers"] = mcp_servers

        agent = sdk.Agent(**agent_kwargs)
        run_config = self._build_run_config(sdk)
        runner = getattr(sdk, "Runner", None)
        if runner is None:
            raise RuntimeError("OpenAI Agents SDK Runner is unavailable")

        result = await runner.run(
            agent,
            input=user_prompt,
            context=context,
            max_turns=self.max_turns,
            run_config=run_config,
        )
        messages = normalize_run_result_messages(result)
        return FrameworkRunResult(
            raw_result=result,
            messages=messages,
            final_output=getattr(result, "final_output", None),
            new_items=list(getattr(result, "new_items", []) or []),
            turns=len(getattr(result, "raw_responses", []) or []),
        )
