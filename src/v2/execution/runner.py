"""Execution runner for the v2 architecture."""

from __future__ import annotations

import importlib
import inspect
import json
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from pydantic import TypeAdapter

from src.utils.parsers import normalize_tool_result, to_jsonable
from src.v2.contracts.execution import (
    AgentExecutionSpec,
    ApprovalEvent,
    ExecutionResult,
    LocalToolSpec,
    ToolCallInterception,
    ToolEvent,
    ToolSpec,
)
from src.v2.execution.policies import ExecutionPolicy
from src.v2.observability import trace_execution_result, trace_execution_start, trace_failure


def _load_agents_sdk(sdk_module: Any | None = None) -> Any:
    """Load the Agents SDK lazily so the repo imports without the dependency."""

    if sdk_module is not None:
        return sdk_module
    try:
        return importlib.import_module("agents")
    except Exception as exc:  # pragma: no cover - depends on runtime environment
        raise RuntimeError("openai-agents is not installed") from exc


def _coerce_mapping(value: Any) -> dict[str, Any]:
    """Convert SDK objects into plain mappings when possible."""

    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "model_dump"):
        dumped = value.model_dump()
        if isinstance(dumped, dict):
            return dict(dumped)
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_")}
    return {}


def _decode_json_object(raw: str | None) -> dict[str, Any]:
    """Decode tool arguments into a JSON object."""

    candidate = str(raw or "").strip()
    if not candidate:
        return {}
    parsed = json.loads(candidate)
    if isinstance(parsed, dict):
        return parsed
    raise ValueError("Tool arguments must decode to an object")


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
            mapping = _coerce_mapping(item)
            text = mapping.get("text")
            if text:
                parts.append(str(text))
        return "\n".join(part for part in parts if part).strip()
    mapping = _coerce_mapping(content)
    if mapping.get("text"):
        return str(mapping["text"])
    return ""


def _normalize_tool_payload(raw: Any, *, tool_name: str, invocation: dict[str, Any]) -> dict[str, Any]:
    """Normalize tool outputs into a shared dict payload shape."""

    normalized = normalize_tool_result(raw)
    if normalized:
        normalized.setdefault("invocation", invocation)
        return normalized

    if isinstance(raw, dict):
        payload = dict(raw)
        payload.setdefault("invocation", invocation)
        return payload

    if isinstance(raw, list):
        return {
            "status": "success",
            "result": raw,
            "tool": tool_name,
            "invocation": invocation,
        }

    if isinstance(raw, str):
        candidate = raw.strip()
        if candidate:
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                parsed.setdefault("invocation", invocation)
                return parsed
            if parsed is not None:
                return {
                    "status": "success",
                    "result": parsed,
                    "tool": tool_name,
                    "invocation": invocation,
                }
        return {
            "status": "success",
            "output": raw,
            "tool": tool_name,
            "invocation": invocation,
        }

    return {
        "status": "success",
        "result": to_jsonable(raw),
        "tool": tool_name,
        "invocation": invocation,
    }


def _normalize_mcp_call_result(result: Any) -> Any:
    """Convert raw MCP call results into text or structured payloads."""

    mapping = _coerce_mapping(result)
    structured = mapping.get("structuredContent")
    if structured is not None:
        return structured

    if "structured_content" in mapping and mapping["structured_content"] is not None:
        return mapping["structured_content"]

    content = mapping.get("content")
    if content:
        text = _extract_content_text(content)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text

    if content is not None:
        return content
    return result


def _coerce_output(output_type: type[Any], raw_output: Any) -> Any:
    """Coerce SDK final output into the declared structured type."""

    if isinstance(raw_output, output_type):
        return raw_output
    return TypeAdapter(output_type).validate_python(raw_output)


@dataclass
class _RunRecorder:
    """Mutable telemetry captured while tools execute."""

    approval_events: list[ApprovalEvent] = field(default_factory=list)
    tool_events: list[ToolEvent] = field(default_factory=list)

    def record_approval(self, *, tool: ToolSpec, approved: bool, reason: str) -> None:
        self.approval_events.append(
            ApprovalEvent(
                tool_name=tool.name,
                approved=approved,
                reason=reason,
                server_name=tool.server_name,
            )
        )

    def record_tool_event(
        self,
        *,
        tool: ToolSpec,
        invocation: dict[str, Any],
        result: dict[str, Any],
        status: str,
        approved: bool | None,
    ) -> None:
        artifacts = result.get("artifacts", []) if isinstance(result.get("artifacts"), list) else []
        self.tool_events.append(
            ToolEvent(
                tool_name=tool.name,
                invocation=invocation,
                source=tool.source,
                server_name=tool.server_name,
                approval_required=tool.approval_required,
                approved=approved,
                result=result,
                status=status,
                artifacts=[item for item in artifacts if isinstance(item, dict)],
            )
        )


class AgentsSDKExecutionRunner:
    """Build and run a v2 agent over local and direct-SDK MCP tools."""

    def __init__(self, *, sdk_module: Any | None = None):
        self._sdk_module = sdk_module

    async def run(
        self,
        spec: AgentExecutionSpec[Any],
        *,
        user_input: str,
        context: Any | None = None,
        policy: ExecutionPolicy | None = None,
    ) -> ExecutionResult[Any]:
        """Execute one agent run and return a typed outcome plus telemetry."""

        sdk = _load_agents_sdk(self._sdk_module)
        self._disable_sdk_tracing(sdk)
        active_policy = policy or ExecutionPolicy()
        recorder = _RunRecorder()
        trace_execution_start(
            agent_name=spec.agent_name,
            model=spec.model.model,
            mcp_server_count=len(spec.mcp_servers),
            local_tool_count=len(spec.local_tools),
            max_turns=spec.max_turns,
        )

        try:
            async with AsyncExitStack() as exit_stack:
                tool_specs = await self._build_tool_specs(sdk, spec, exit_stack)
                function_tools = [self._build_function_tool(sdk, tool, active_policy, recorder) for tool in tool_specs]

                agent_kwargs: dict[str, Any] = {
                    "name": spec.agent_name,
                    "instructions": spec.instructions,
                    "output_type": self._build_output_schema(sdk, spec.output_type),
                    "tools": function_tools,
                }

                run_config = self._build_run_config(sdk, spec)
                model = self._build_model(sdk, spec)
                if model is not None:
                    agent_kwargs["model"] = model
                elif spec.model.model:
                    agent_kwargs["model"] = spec.model.model

                agent = sdk.Agent(**agent_kwargs)
                runner = getattr(sdk, "Runner", None)
                if runner is None:
                    raise RuntimeError("OpenAI Agents SDK Runner is unavailable")

                result = await runner.run(
                    agent,
                    user_input,
                    context=context,
                    max_turns=spec.max_turns,
                    run_config=run_config,
                )

            outcome = _coerce_output(spec.output_type, getattr(result, "final_output", None))
            artifacts: list[dict[str, Any]] = []
            for event in recorder.tool_events:
                artifacts.extend(event.artifacts)
            execution_result = ExecutionResult(
                outcome=outcome,
                tool_events=recorder.tool_events,
                approval_events=recorder.approval_events,
                artifacts=artifacts,
                raw_result=result,
            )
            trace_execution_result(agent_name=spec.agent_name, result=execution_result)
            return execution_result
        except Exception as exc:
            trace_failure(lane="execution", agent_name=spec.agent_name, exc=exc)
            raise

    async def _build_tool_specs(
        self,
        sdk: Any,
        spec: AgentExecutionSpec[Any],
        exit_stack: AsyncExitStack,
    ) -> list[ToolSpec]:
        """Resolve all local and MCP-backed tools for a run."""

        tool_specs = [self._build_local_tool_spec(tool) for tool in spec.local_tools]
        tool_specs.extend(await self._build_mcp_tool_specs(sdk, spec, exit_stack))
        if not tool_specs:
            raise RuntimeError("No tools were available for this execution")
        return tool_specs

    def _build_local_tool_spec(self, tool: LocalToolSpec) -> ToolSpec:
        """Convert a local tool declaration into the runtime tool shape."""

        return ToolSpec(
            name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            executor=tool.executor,
            source="local",
            defaults=dict(tool.defaults),
            approval_required=tool.approval_required,
        )

    async def _build_mcp_tool_specs(
        self,
        sdk: Any,
        spec: AgentExecutionSpec[Any],
        exit_stack: AsyncExitStack,
    ) -> list[ToolSpec]:
        """Connect to MCP servers directly through the SDK and wrap listed tools."""

        mcp_module = getattr(sdk, "mcp", None)
        if mcp_module is None:
            try:
                mcp_module = importlib.import_module("agents.mcp")
            except Exception as exc:  # pragma: no cover - depends on runtime environment
                raise RuntimeError("OpenAI Agents SDK MCP helpers are unavailable") from exc

        server_cls = getattr(mcp_module, "MCPServerStreamableHttp", None)
        static_filter = getattr(mcp_module, "create_static_tool_filter", None)
        if server_cls is None:
            raise RuntimeError("OpenAI Agents SDK MCPServerStreamableHttp is unavailable")

        tool_specs: list[ToolSpec] = []
        for server_config in spec.mcp_servers:
            server_kwargs: dict[str, Any] = {
                "name": server_config.name,
                "params": {"url": server_config.url},
                "cache_tools_list": server_config.cache_tools_list,
            }
            if server_config.allowed_tools and static_filter is not None:
                server_kwargs["tool_filter"] = static_filter(
                    allowed_tool_names=sorted(server_config.allowed_tools)
                )
            server = server_cls(**server_kwargs)
            if hasattr(server, "__aenter__") and hasattr(server, "__aexit__"):
                server = await exit_stack.enter_async_context(server)
            else:
                connect = getattr(server, "connect", None)
                close = getattr(server, "close", None)
                if callable(connect):
                    await connect()
                if callable(close):
                    exit_stack.push_async_callback(close)

            tools_result = await server.list_tools()
            listed_tools = getattr(tools_result, "tools", tools_result)
            for raw_tool in listed_tools or []:
                tool_name = self._tool_name(raw_tool)
                if server_config.allowed_tools and tool_name not in server_config.allowed_tools:
                    continue
                tool_specs.append(
                    ToolSpec(
                        name=tool_name,
                        description=self._tool_description(raw_tool),
                        input_schema=self._tool_schema(raw_tool),
                        executor=self._build_mcp_executor(server, tool_name),
                        source="mcp",
                        server_name=server_config.name,
                        approval_required=tool_name in server_config.approval_required_tools,
                    )
                )
        return tool_specs

    def _build_mcp_executor(self, server: Any, tool_name: str):
        """Build an executor that calls one MCP tool through the SDK."""

        async def execute(**kwargs: Any) -> Any:
            result = await server.call_tool(tool_name, kwargs)
            return _normalize_mcp_call_result(result)

        return execute

    def _tool_name(self, tool_def: Any) -> str:
        """Extract a tool name from an MCP tool definition."""

        if isinstance(tool_def, dict):
            return str(tool_def.get("name") or "")
        return str(getattr(tool_def, "name", "") or "")

    def _tool_description(self, tool_def: Any) -> str:
        """Extract a tool description from an MCP tool definition."""

        if isinstance(tool_def, dict):
            return str(tool_def.get("description") or tool_def.get("name") or "")
        return str(getattr(tool_def, "description", "") or getattr(tool_def, "name", ""))

    def _tool_schema(self, tool_def: Any) -> dict[str, Any]:
        """Extract an MCP input schema from a tool definition."""

        if isinstance(tool_def, dict):
            schema = tool_def.get("inputSchema") or tool_def.get("input_schema") or {}
        else:
            schema = getattr(tool_def, "inputSchema", None) or getattr(tool_def, "input_schema", None) or {}
        if isinstance(schema, dict):
            return dict(schema)
        return {"type": "object", "properties": {}}

    def _build_function_tool(
        self,
        sdk: Any,
        tool: ToolSpec,
        policy: ExecutionPolicy,
        recorder: _RunRecorder,
    ) -> Any:
        """Convert one runtime tool into an SDK function tool."""

        function_tool_cls = getattr(sdk, "FunctionTool", None)
        if function_tool_cls is None:
            raise RuntimeError("OpenAI Agents SDK FunctionTool is unavailable")

        async def on_invoke_tool(run_context: Any, args_json: str) -> str:
            invocation = _decode_json_object(args_json)
            invocation = {**tool.defaults, **invocation}
            approved: bool | None = None

            if tool.approval_required:
                approved = await policy.approve_tool_call(tool, dict(invocation))
                recorder.record_approval(
                    tool=tool,
                    approved=approved,
                    reason="approval_required" if approved else "approval_rejected",
                )
                if not approved:
                    payload = _normalize_tool_payload(
                        {
                            "status": "aborted",
                            "message": "Execution blocked pending manual approval.",
                            "tool": tool.name,
                        },
                        tool_name=tool.name,
                        invocation=invocation,
                    )
                    recorder.record_tool_event(
                        tool=tool,
                        invocation=invocation,
                        result=payload,
                        status=str(payload.get("status", "aborted")),
                        approved=False,
                    )
                    return json.dumps(payload, indent=2, default=str)

            intercepted = await policy.before_tool_call(tool, dict(invocation))
            if isinstance(intercepted, ToolCallInterception):
                payload = _normalize_tool_payload(
                    intercepted.payload,
                    tool_name=tool.name,
                    invocation=invocation,
                )
                recorder.record_tool_event(
                    tool=tool,
                    invocation=invocation,
                    result=payload,
                    status=str(payload.get("status", "blocked")),
                    approved=approved,
                )
                return json.dumps(payload, indent=2, default=str)

            try:
                raw_result = await tool.executor(**invocation)
                policy_result = await policy.after_tool_call(tool, dict(invocation), raw_result)
                payload = _normalize_tool_payload(
                    policy_result,
                    tool_name=tool.name,
                    invocation=invocation,
                )
            except Exception as exc:
                payload = _normalize_tool_payload(
                    {
                        "status": "error",
                        "message": f"{tool.name} failed: {exc}",
                        "tool": tool.name,
                    },
                    tool_name=tool.name,
                    invocation=invocation,
                )

            recorder.record_tool_event(
                tool=tool,
                invocation=invocation,
                result=payload,
                status=str(payload.get("status", "success")),
                approved=approved,
            )
            return json.dumps(payload, indent=2, default=str)

        return function_tool_cls(
            name=tool.name,
            description=tool.description or tool.name,
            params_json_schema=tool.input_schema or {"type": "object", "properties": {}},
            on_invoke_tool=on_invoke_tool,
        )

    def _build_output_schema(self, sdk: Any, output_type: type[Any]) -> Any:
        """Wrap Pydantic outputs for SDKs that require strict JSON schemas by default."""

        output_schema_cls = getattr(sdk, "AgentOutputSchema", None)
        if output_schema_cls is None:
            return output_type
        try:
            return output_schema_cls(output_type, strict_json_schema=False)
        except TypeError:
            return output_type

    def _disable_sdk_tracing(self, sdk: Any) -> None:
        """Disable SDK-native trace export; v2 uses its own redacted trace logs."""

        set_disabled = getattr(sdk, "set_tracing_disabled", None)
        if callable(set_disabled):
            try:
                set_disabled(True)
            except TypeError:
                set_disabled(disabled=True)

    def _build_model(self, sdk: Any, spec: AgentExecutionSpec[Any]) -> Any | None:
        """Build a model object when the SDK expects one instead of a model string."""

        if getattr(sdk, "OpenAIProvider", None) is not None and getattr(sdk, "RunConfig", None) is not None:
            return None

        async_openai_cls = getattr(sdk, "AsyncOpenAI", None)
        chat_model_cls = getattr(sdk, "OpenAIChatCompletionsModel", None)
        if async_openai_cls is None or chat_model_cls is None:
            return None

        client_kwargs: dict[str, Any] = {
            "api_key": spec.model.api_key,
            "base_url": spec.model.base_url,
        }
        if spec.model.timeout_seconds is not None:
            client_kwargs["timeout"] = spec.model.timeout_seconds
        client = async_openai_cls(**client_kwargs)
        return chat_model_cls(model=spec.model.model, openai_client=client)

    def _build_run_config(self, sdk: Any, spec: AgentExecutionSpec[Any]) -> Any:
        """Build run config and provider wiring when the SDK exposes them."""

        run_config_cls = getattr(sdk, "RunConfig", None)
        if run_config_cls is None:
            return None

        kwargs: dict[str, Any] = {}
        model_settings_cls = getattr(sdk, "ModelSettings", None)
        if model_settings_cls is not None:
            kwargs["model_settings"] = self._build_model_settings_instance(
                model_settings_cls,
                {"temperature": spec.model.temperature},
            )

        provider_cls = getattr(sdk, "OpenAIProvider", None)
        if provider_cls is not None:
            kwargs["model_provider"] = provider_cls(
                api_key=spec.model.api_key,
                base_url=spec.model.base_url,
            )
            kwargs["model"] = spec.model.model

        if spec.model.trace_include_sensitive_data:
            kwargs["trace_include_sensitive_data"] = True

        kwargs["tracing_disabled"] = True
        return self._build_run_config_instance(run_config_cls, kwargs)

    def _build_run_config_instance(self, run_config_cls: Any, kwargs: dict[str, Any]) -> Any:
        """Instantiate RunConfig while tolerating SDK version differences."""

        try:
            signature = inspect.signature(run_config_cls)
            parameters = signature.parameters
            supported = set(parameters)
        except (TypeError, ValueError):
            parameters = {}
            supported = set()
        if supported and not any(param.kind == inspect.Parameter.VAR_KEYWORD for param in parameters.values()):
            kwargs = {key: value for key, value in kwargs.items() if key in supported}
        try:
            return run_config_cls(**kwargs)
        except TypeError:
            kwargs.pop("tracing_disabled", None)
            return run_config_cls(**kwargs)

    def _build_model_settings_instance(self, model_settings_cls: Any, kwargs: dict[str, Any]) -> Any:
        """Instantiate ModelSettings while tolerating SDK version differences."""

        try:
            signature = inspect.signature(model_settings_cls)
            parameters = signature.parameters
            supported = set(parameters)
        except (TypeError, ValueError):
            parameters = {}
            supported = set()
        if supported and not any(param.kind == inspect.Parameter.VAR_KEYWORD for param in parameters.values()):
            kwargs = {key: value for key, value in kwargs.items() if key in supported}
        return model_settings_cls(**kwargs)
