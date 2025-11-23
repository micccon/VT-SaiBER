"""
Prompt Engineer ("Tony Stark")

This module is responsible for constructing the precise prompts that are
sent to the LLM. It combines the user's query with system instructions,
the agent registry, and any relevant context or memory.
"""
import json
from typing import Any
from orchestrator.interfaces import IPromptBuilder
from interaction.api.thanos import process_user_input

class StarkPromptEngine(IPromptBuilder):

    def __init__(self):
        self.default_prompts = {
            "general": "Please respond to the following user input:\n{user_input}",
            "security_scan": (
                "You are a cybersecurity expert. Write a Python script that performs a security scan using modern best practices.\n"
                "Task description: {user_input}\n"
                "Explain your implementation approach."
            ),
            "summarize": (
                "Summarize the following text into five key bullet points:\n{user_input}"
            )
        }

    def build_prompt(self, user_query: Any, agent_registry: dict = None, context: dict = None) -> str:
        """
        Build a prompt. This method is compatible with `IPromptBuilder.build_prompt`.

        `user_query` may be:
          - a raw string (user input)
          - a dict produced by `interaction.api.thanos.extract_command`
        """
        # Normalize to a structured dict if possible
        cmd = None
        if isinstance(user_query, str):
            try:
                # try to parse as JSON command
                cmd = json.loads(user_query)
            except Exception:
                # fallback: run processor to get structured command (JSON string)
                try:
                    cmd = json.loads(process_user_input(user_query, output_context="json"))
                except Exception:
                    cmd = {"raw": user_query, "action": "general"}
        elif isinstance(user_query, dict):
            cmd = user_query
        else:
            cmd = {"raw": str(user_query), "action": "general"}

        action = cmd.get("action", "general")

        # Build a human-readable user_input snippet for the templates
        if action in ("port_scan", "service_scan", "ping_scan", "quick_scan"):
            # Prefer sanitized targets if available. sanitized_targets may be list of dicts or strings.
            raw_sanitized = cmd.get("sanitized_targets") or cmd.get("targets") or []
            targets = []
            for t in raw_sanitized:
                if isinstance(t, dict):
                    # prefer the sanitized 'value' then 'raw'
                    v = t.get("value") or t.get("raw")
                    if v:
                        targets.append(str(v))
                else:
                    targets.append(str(t))
            ports = cmd.get("ports") or []
            target_str = ", ".join(targets) if targets else cmd.get("raw", "")
            params = []
            if ports:
                params.append(f"ports: {', '.join(ports)}")
            params_str = ("; ".join(params)) if params else ""
            user_input_text = f"Action: {action}. Targets: {target_str}. {params_str}"
            template = self.default_prompts.get("security_scan")
            return template.format(user_input=user_input_text)

        # default/general
        user_text = cmd.get("raw", "")
        template = self.default_prompts.get("general")
        return template.format(user_input=user_text)

    def list_available_prompts(self) -> list:
        return list(self.default_prompts.keys())

# Example usage
if __name__ == "__main__":
    raw_input = input("Enter your command: ")
    # Produce a structured command and build prompt from it
    cmd_json = process_user_input(raw_input, output_context="json")
    builder = StarkPromptEngine()
    prompt = builder.build_prompt(cmd_json)
    
    print("\nGenerated LLM prompt:\n")
    print(prompt)
        