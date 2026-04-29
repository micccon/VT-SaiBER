"""Striker v2 built on the new Agents SDK execution framework."""

from __future__ import annotations

import os
import inspect
from typing import Any, Dict, List

from src.agents.base import BaseAgent
from src.agents.execution import AgentsExecutionEngine
from src.agents.striker_core import (
    MAX_EXPLOIT_ATTEMPTS,
    STRIKER_ALLOWED_TOOLS,
    StrikerToolPolicy,
    build_striker_context,
    extract_striker_updates,
)
from src.config import get_runtime_config
from src.skills import match_skills
from src.state.cyber_state import CyberState
from src.utils.tools import load_filtered_tools

STRIKER_V2_REQUIRE_CONFIRMATION = (
    os.getenv("STRIKER_V2_REQUIRE_CONFIRMATION")
    or os.getenv("STRIKER_REQUIRE_CONFIRMATION")
    or "true"
).strip().lower() == "true"
STRIKER_V2_MAX_ATTEMPTS = int(os.getenv("STRIKER_V2_MAX_ATTEMPTS", str(MAX_EXPLOIT_ATTEMPTS)))


STRIKER_V2_SYSTEM_PROMPT = """You are the VT-SaiBER striker exploitation specialist.
Use only the provided MCP tools and the mission context.

Metasploit: msf_search_modules, msf_get_module_info, msf_get_module_options, msf_run_exploit, msf_run_auxiliary, msf_list_sessions.
Attackbox: web_sqlmap_scan, access_hydra_attack, access_smb_enum, web_wordpress_scan, system_execute_command.

Rules:
1. Work only from the mission context and discovered evidence.
2. Prefer one strong evidence-backed path at a time; do not bounce between weak ideas.
3. Use Metasploit for module-driven exploitation and session-oriented execution; use attackbox tools for focused validation and credential/web paths.
4. Search with narrow evidence-based terms derived from service, version, platform, or CVE.
5. Reverse payloads require a reachable non-loopback LHOST; never use 127.0.0.1, localhost, or 0.0.0.0.
6. After every Metasploit execution attempt, check msf_list_sessions.
7. Maximum Metasploit execution attempts per run: {max_attempts}.

Metasploit doctrine:
- Use Metasploit when the evidence suggests a module-driven path, a CVE-backed path, or a service that maps cleanly to a known exploit or auxiliary family.
- Search with narrow service, product, version, banner, or CVE terms.
- Prefer exact evidence-backed modules over broad exploratory searches.
- Inspect module info and module options before execution.
- Fill only the minimum required options from observed evidence.
- Use auxiliary modules for validation, login checks, or service interrogation when they advance the path.
- Verify success with msf_list_sessions; module output alone is not enough.
- Pivot away from Metasploit when no module family matches cleanly or the path depends mostly on guessed options.

Attackbox doctrine:
- Use attackbox tools when the evidence favors a focused web, credential, SMB, WordPress, or protocol-validation path rather than a Metasploit module.
- Choose one primary tool for the current hypothesis.
- Keep tool arguments tightly scoped to observed hosts, paths, forms, services, or interfaces.
- Use web_sqlmap_scan for strong SQL injection hypotheses.
- Use access_hydra_attack only when the service and credential hypothesis are evidence-backed.
- Use access_smb_enum for SMB evidence gathering.
- Use web_wordpress_scan for WordPress-specific paths.
- Use system_execute_command only for precise validation that the dedicated tools do not cover.
- Pivot away from attackbox tools when the path now clearly maps to a strong Metasploit module family or the current tool idea failed cleanly with no new evidence.

Path selection:
- Favor the strongest evidence-backed path over the most tunable path.
- One clean no-session failure should lower confidence in that path.
- After a no-session failure, pivot meaningfully unless genuinely new evidence justifies retrying.
- Do not keep refining a weak exploit path with small guessed changes.

Option selection:
- Inspect module options before execution and set required options explicitly from known evidence.
- Prefer the minimum viable option set and avoid invented values.
- Only set path-like, host/domain-like, TLS, auth, or callback options when supported by mission context, observed findings, or tool output.
- If TARGETURI, PATH, URI, DOMAIN, VHOST, SSL, SSLVersion, USERNAME, PASSWORD, LHOST, or callback settings are uncertain, omit them or gather more evidence.

Finish with a concise summary of what was attempted, why each path was chosen, and whether access or validation succeeded."""


class StrikerV2Agent(BaseAgent):
    """Striker variant that runs through the new Agents SDK execution engine."""

    ALLOWED_TOOLS = STRIKER_ALLOWED_TOOLS

    def __init__(self, *, sdk_module: Any | None = None):
        super().__init__("striker", "Unified Exploitation Agent v2")
        self._sdk_module = sdk_module
        self._config = get_runtime_config()
        self.require_confirmation = STRIKER_V2_REQUIRE_CONFIRMATION
        self.max_attempts = STRIKER_V2_MAX_ATTEMPTS

    @property
    def system_prompt(self) -> str:
        return STRIKER_V2_SYSTEM_PROMPT.format(max_attempts=self.max_attempts)

    async def _load_runtime_tools(self):
        resolved = load_filtered_tools(self.ALLOWED_TOOLS)
        if inspect.isawaitable(resolved):
            resolved = await resolved
        return resolved

    def _extract_updates(self, messages: List[Dict[str, Any]], state: CyberState, context: str) -> Dict[str, Any]:
        matched_skill_names = [match.skill.relative_path for match in match_skills(state, self.name, limit=2)]
        return extract_striker_updates(
            messages,
            state,
            context,
            matched_skill_names=matched_skill_names,
            current_agent=self.name,
            base_update=self._agent_update(state),
            log_action_payload=self.log_action(
                state,
                action="run_exploit",
                target=None,
                findings=None,
                reasoning=context,
            ),
        )

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        if not (state.get("discovered_targets", {}) or {}):
            return self._error_update(
                state,
                error_type="ValidationError",
                message="No discovered targets available for striker exploitation.",
                recoverable=True,
            )

        context = build_striker_context(state)
        try:
            runtime_tools = await self._load_runtime_tools()
            if not runtime_tools:
                raise RuntimeError("No allowed tools were available from the MCP bridge")

            framework = AgentsExecutionEngine(
                agent_name=self.name,
                instructions=self.system_prompt,
                model_name=self._config.openrouter_model,
                api_key=self._config.openrouter_api_key,
                base_url=self._config.openrouter_base_url,
                timeout_seconds=self._config.supervisor_timeout_seconds,
                runtime_tools=runtime_tools,
                policy=StrikerToolPolicy(
                    require_confirmation=self.require_confirmation,
                    max_attempts=self.max_attempts,
                ),
                max_turns=8,
                temperature=0.0,
                trace_include_sensitive_data=False,
            )
            run_result = await framework.run(user_prompt=context, context=state, sdk_module=self._sdk_module)
            if not run_result.messages and run_result.final_output is not None:
                run_result.messages = [{"role": "assistant", "content": run_result.final_output}]
            return self._extract_updates(run_result.messages, state, context)
        except Exception as exc:
            return self._error_update(
                state,
                error_type="LLMError",
                message=f"Striker v2 execution failed. {exc}",
                recoverable=False,
            )


async def striker_v2_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper for the Striker v2 agent."""

    from src.database.persistence import persist_state_update

    updates = await StrikerV2Agent().call_llm(state)
    persist_state_update(state, updates)
    return updates
