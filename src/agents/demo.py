"""
Demo Agent - Example implementation using Gemini API

This demonstrates how to:
1. Inherit from BaseAgent
2. Use Gemini for reasoning
3. Return validated Pydantic outputs
4. Update shared CyberState

Run with: python -m src.agents.demo
"""

import asyncio
import json
import re
import os
from typing import Dict, Any, Type, TypeVar
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from google import genai
from langsmith import traceable
from src.agents.base import BaseAgent
from src.state.cyber_state import CyberState
from src.state.models import (
    DiscoveredTarget,
    ServiceInfo,
    SupervisorDecision,
)

T = TypeVar("T")
os.environ["LANGSMITH_TRACING"] = "true"
os.environ["LANGSMITH_WORKSPACE_ID"] = os.getenv("LANGSMITH_WORKSPACE_ID", "")
os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
os.environ["LANGSMITH_API_KEY"] = os.getenv("LANGSMITH_API_KEY", "")

# ============================================================================
# LLM CLIENT (Gemini)
# ============================================================================

class GeminiClient:
    """Async Gemini API wrapper; runs sync SDK in thread to avoid blocking."""

    def __init__(self, model: str = "gemini-2.5-flash"):
        self.client = genai.Client()
        self.model = model

    @traceable
    def _generate_sync(self, system_prompt: str, user_prompt: str) -> str:
        """Synchronous generate_content (run in executor for async)."""
        response = self.client.models.generate_content(
            model=self.model,
            contents=[
                {"parts": [{"text": system_prompt}]},
                {"parts": [{"text": user_prompt}]},
            ],
        )
        return response.text or ""

    async def ask(self, system_prompt: str, user_prompt: str) -> str:
        """Send a prompt to Gemini and return raw text (non-blocking)."""
        return await asyncio.to_thread(
            self._generate_sync, system_prompt, user_prompt
        )

    @staticmethod
    def _extract_json(text: str) -> str:
        """Extract JSON object or array from markdown code block or raw text."""
        text = text.strip()
        # Try ```json ... ``` or ``` ... ```
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if match:
            return match.group(1).strip()
        # Find first { or [ to last } or ]
        start = min(
            (text.find(c) for c in ("{", "[") if text.find(c) >= 0),
            default=-1,
        )
        if start < 0:
            return text
        depth = 0
        open_c, close_c = ("{", "}") if text[start] == "{" else ("[", "]")
        for i in range(start, len(text)):
            if text[i] == open_c:
                depth += 1
            elif text[i] == close_c:
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
        return text[start:]

    async def ask_json(
        self,
        system_prompt: str,
        user_prompt: str,
        model_class: Type[T] | None = None,
    ) -> Dict[str, Any] | T:
        """Call LLM, parse JSON from response, optionally validate as Pydantic model."""
        raw = await self.ask(system_prompt, user_prompt)
        json_str = self._extract_json(raw)
        data = json.loads(json_str)
        if model_class is not None:
            return model_class.model_validate(data)
        return data


# ============================================================================
# SCOUT AGENT (Demo Implementation)
# ============================================================================

class ScoutAgent(BaseAgent):
    """Demo agent that performs network reconnaissance using Gemini."""

    def __init__(self):
        super().__init__("scout", "Network Reconnaissance Specialist")
        self.llm = GeminiClient()

    @property
    def system_prompt(self) -> str:
        return """You are a network reconnaissance specialist. Your goal is to:
        1. Analyze target IPs and discover open ports
        2. Identify services running on those ports
        3. Return findings in a structured JSON format

        Be thorough but efficient. Focus on actionable intelligence."""

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """
        Main reasoning loop for the Scout agent.

        Flow:
        1. Read target_scope from state
        2. Ask Gemini what to scan
        3. Simulate scan results (in real version, would call MCP tools)
        4. Return validated state updates
        """
        # Step 1: Get targets from state
        target_scope = state.get("target_scope", [])
        if not target_scope:
            return self.log_error(
                state,
                error_type="ValidationError",
                error="No targets in target_scope",
            )

        target_ip = target_scope[0]
        print(f"\n[Scout] Analyzing target: {target_ip}")

        # Step 2: Validate scope (safety check)
        if not self.validate_scope(target_ip, target_scope):
            return self.log_error(
                state,
                error_type="ScopeViolation",
                error=f"Target {target_ip} not in scope",
            )

        # Step 3: Use Gemini to plan reconnaissance (real LLM call)
        user_prompt = f"""
Target: {target_ip}
Scope: {target_scope}

Respond with exactly one JSON object (no other text) with:
- "ports_to_scan": array of port numbers to scan (e.g. [22, 80, 443])
- "scan_strategy": one of "quick", "standard", "deep"
"""
        try:
            plan = await self.llm.ask_json(
                self.system_prompt,
                user_prompt,
            )
            ports_to_scan = plan.get("ports_to_scan") or [22, 80, 443]
            if not isinstance(ports_to_scan, list):
                ports_to_scan = [22, 80, 443]
            ports_to_scan = [int(p) for p in ports_to_scan if isinstance(p, (int, float))][:20]
            if not ports_to_scan:
                ports_to_scan = [22, 80, 443]
        except (json.JSONDecodeError, TypeError) as e:
            ports_to_scan = [22, 80, 443]
            print(f"[Scout] LLM parse fallback: {e}")

        # In real implementation: call self.mcp.call_tool("nmap", {...})
        # Here: simulate scan results for chosen ports
        default_services = {
            22: ServiceInfo(port=22, service_name="ssh", version="OpenSSH 8.2p1", banner="SSH-2.0-OpenSSH_8.2p1"),
            80: ServiceInfo(port=80, service_name="http", version="Apache 2.4.41", banner=None),
            443: ServiceInfo(port=443, service_name="https", version="Apache 2.4.41", banner=None),
            8080: ServiceInfo(port=8080, service_name="http-proxy", version="Unknown", banner=None),
            21: ServiceInfo(port=21, service_name="ftp", version="vsftpd 3.0.3", banner=None),
        }
        simulated_services = {
            p: default_services.get(
                p,
                ServiceInfo(port=p, service_name="unknown", version=None, banner=None),
            )
            for p in ports_to_scan
        }

        # Step 4: Build validated target
        target = DiscoveredTarget(
            ip_address=target_ip,
            ports=ports_to_scan,
            services=simulated_services,
            os_guess="Linux (Ubuntu 20.04)",
        )

        print(f"[Scout] Discovered {len(target.ports)} ports on {target_ip}")

        # Step 5: Return state updates
        return {
            "discovered_targets": {target_ip: target.model_dump()},
            **self.log_action(
                state,
                action="port_scan",
                target=target_ip,
                findings={"ports_found": target.ports, "services": 3},
                reasoning="Discovered 3 open ports: SSH, HTTP, HTTPS",
            ),
        }


# ============================================================================
# SUPERVISOR AGENT (Demo Implementation)
# ============================================================================

class SupervisorAgent(BaseAgent):
    """Demo supervisor that routes to other agents using Gemini."""

    def __init__(self):
        super().__init__("supervisor", "Mission Coordinator")
        self.llm = GeminiClient()

    @property
    def system_prompt(self) -> str:
        return """You are the supervisor of a security testing team.
        Your job is to:
        1. Review the current mission state
        2. Decide which specialist agent to call next
        3. Explain your reasoning

        Available agents:
        - scout: Discover targets and open ports
        - fuzzer: Find web vulnerabilities
        - striker: Exploit found vulnerabilities

        Return your decision in JSON format."""

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """Decide next agent based on current state (real LLM call)."""
        context = f"""
Mission Goal: {state.get('mission_goal', 'Unknown')}
Iteration: {state.get('iteration_count', 0)}
Mission Status: {state.get('mission_status', 'active')}

Discovered Targets: {list(state.get('discovered_targets', {}).keys())}
Web Findings count: {len(state.get('web_findings', []))}
Active Sessions: {state.get('active_sessions', {})}

Respond with exactly one JSON object (no other text) with:
- "next_agent": one of "scout", "fuzzer", "striker", "end"
- "rationale": short reasoning for this choice
- "specific_goal": one sentence task for the chosen agent (or "N/A" if end)
- "confidence_score": number between 0.0 and 1.0
"""
        try:
            decision = await self.llm.ask_json(
                self.system_prompt,
                context,
                model_class=SupervisorDecision,
            )
            next_agent = decision.next_agent.strip().lower()
            if next_agent not in ("scout", "fuzzer", "striker", "end"):
                next_agent = "scout"
            rationale = decision.rationale or "No rationale provided."
        except (json.JSONDecodeError, TypeError, Exception) as e:
            # Fallback routing logic
            targets = state.get("discovered_targets", {})
            if not targets:
                next_agent, rationale = "scout", "No targets yet; starting reconnaissance."
            elif len(state.get("web_findings", [])) == 0:
                next_agent, rationale = "fuzzer", "Targets found; running web fuzzer."
            else:
                next_agent, rationale = "striker", "Web findings present; exploitation phase."
            print(f"[Supervisor] LLM fallback: {e}")

        print(f"\n[Supervisor] Decision: {next_agent}")
        print(f"[Supervisor] Rationale: {rationale}")

        return {
            "next_agent": next_agent,
            "iteration_count": state.get("iteration_count", 0) + 1,
            **self.log_action(
                state,
                action="route_decision",
                decision=next_agent,
                reasoning=rationale,
            ),
        }


# ============================================================================
# STUB AGENTS (for orchestration; full impl would use MCP/tools)
# ============================================================================

class FuzzerAgent(BaseAgent):
    """Stub: web fuzzer; in production would call MCP fuzzer tools."""

    def __init__(self):
        super().__init__("fuzzer", "Web Fuzzing Specialist")
        self.llm = GeminiClient()

    @property
    def system_prompt(self) -> str:
        return "You are a web fuzzing specialist. Enumerate paths and find interesting endpoints."

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        print("\n[Fuzzer] (stub) Would run web path fuzzing on discovered targets.")
        return {
            "web_findings": [],
            **self.log_action(
                state,
                action="fuzzer_stub",
                reasoning="Stub run; no real fuzzing. Add web_findings in full impl.",
            ),
        }


class StrikerAgent(BaseAgent):
    """Stub: exploitation; in production would call MCP/Striker tools."""

    def __init__(self):
        super().__init__("striker", "Exploitation Specialist")
        self.llm = GeminiClient()

    @property
    def system_prompt(self) -> str:
        return "You are an exploitation specialist. Use findings to gain access."

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        print("\n[Striker] (stub) Would run exploits based on web findings.")
        return {
            **self.log_action(
                state,
                action="striker_stub",
                reasoning="Stub run; no real exploitation.",
            ),
        }


# ============================================================================
# DEMO RUNNER & ORCHESTRATION
# ============================================================================

def merge_state(state: CyberState, update: Dict[str, Any]) -> CyberState:
    """Merge agent update into state; accumulate agent_log and errors."""
    merged = {**state, **update}
    # Append list fields instead of overwriting
    for key in ("agent_log", "errors", "critical_findings", "web_findings"):
        existing = state.get(key)
        if isinstance(existing, list) and key in update and isinstance(update[key], list):
            merged[key] = list(existing) + list(update[key])
    # Merge discovered_targets dict
    if "discovered_targets" in update and isinstance(update["discovered_targets"], dict):
        merged["discovered_targets"] = {**state.get("discovered_targets", {}), **update["discovered_targets"]}
    return merged


async def demo_run(max_iterations: int = 5):
    """Run multi-agent demo: supervisor orchestrates scout / fuzzer / striker with real LLM calls."""

    state: CyberState = {
        "current_agent": "",
        "next_agent": "scout",
        "iteration_count": 0,
        "mission_status": "active",
        "mission_goal": "Exploit 192.168.1.50",
        "target_scope": ["192.168.1.0/24"],
        "discovered_targets": {},
        "web_findings": [],
        "active_sessions": {},
        "exploited_services": [],
        "research_cache": {},
        "osint_findings": [],
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }

    supervisor = SupervisorAgent()
    agents: Dict[str, BaseAgent] = {
        "scout": ScoutAgent(),
        "fuzzer": FuzzerAgent(),
        "striker": StrikerAgent(),
    }

    print("=" * 60)
    print("VT-SaiBER Demo Run (LLM orchestration)")
    print("=" * 60)
    print(f"\nInitial State:")
    print(f"  Mission: {state['mission_goal']}")
    print(f"  Scope: {state['target_scope']}")
    print(f"  Max iterations: {max_iterations}")

    # Orchestration loop: supervisor -> worker -> merge until "end" or max_iter
    for step in range(max_iterations):
        print("\n" + "-" * 40)
        # 1) Supervisor decides next agent
        update = await supervisor.call_llm(state)
        state = merge_state(state, update)
        next_agent = state.get("next_agent", "scout")

        if next_agent == "end":
            print("\n[Supervisor] Mission end requested.")
            state["mission_status"] = "active"  # or "success" if goal met
            break

        # 2) Run chosen agent
        worker = agents.get(next_agent)
        if not worker:
            print(f"\n[Orchestrator] Unknown agent '{next_agent}', defaulting to scout.")
            worker = agents["scout"]
        state["current_agent"] = next_agent
        update = await worker.call_llm(state)
        state = merge_state(state, update)

    # Show final state summary
    print("\n" + "=" * 60)
    print("Final State Summary")
    print("=" * 60)
    print(f"  Iteration: {state['iteration_count']}")
    print(f"  Next Agent: {state['next_agent']}")
    print(f"  Targets Found: {len(state['discovered_targets'])}")
    print(f"  Agent Log Entries: {len(state['agent_log'])}")
    print(f"  Errors: {len(state['errors'])}")

    # Show discovered targets
    for ip, data in state.get("discovered_targets", {}).items():
        print(f"\n  Target: {ip}")
        print(f"    OS: {data.get('os_guess', 'Unknown')}")
        print(f"    Ports: {data.get('ports', [])}")

    # Show agent log (entries are AgentLogEntry from base.log_action)
    print("\n  Agent Log:")
    for entry in state.get("agent_log", []):
        if isinstance(entry, dict):
            agent = entry.get("agent", "?")
            action = entry.get("action", "?")
        else:
            agent = getattr(entry, "agent", "?")
            action = getattr(entry, "action", "?")
        print(f"    - {agent}: {action}")

    return state


if __name__ == "__main__":
    # Set Google API key from environment
    os.environ["GOOGLE_API_KEY"] = os.getenv("GEMINI_API_KEY", "")

    result = asyncio.run(demo_run())
