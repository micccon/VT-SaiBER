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
from pathlib import Path
import copy

DEFAULT_FORMAT_ARGS = {
    "user_input": "[NO INPUT PROVIDED]",
    "allowed_targets": "[NOT SPECIFIED]",
    "port_range": "1-65535",
    "rate_limit": "20",
    "constraints": "Non-destructive only.",
}

class StarkPromptEngine(IPromptBuilder):
    _PROMPT_CACHE = None
    _PROMPT_PATH = Path(__file__).resolve().parents[1] / "database" / "avenger_prompts" / "tony_stark_prompt_example.json"

    def __init__(self):
        # Load prompts from file to cache once
        if StarkPromptEngine._PROMPT_CACHE is None:
            prompts_path = self._PROMPT_PATH
            if not prompts_path.exists():
                prompts_path = Path.cwd() / "database" / "avenger_prompts" / "tony_stark_prompt_example.json"
            try:
                with open(prompts_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    # if any value is a list, join into string
                    for k, v in loaded.items():
                        if isinstance(v, list):
                            loaded[k] = "\n".join(str(x) for x in v)
                    StarkPromptEngine._PROMPT_CACHE = loaded
            except Exception:
                # Fallback to hardcoded defaults
                StarkPromptEngine._PROMPT_CACHE = {
                    "general": "Please respond to the following user input:\n{user_input}",
                    "security_scan": (
                        "You are a cybersecurity expert. Write a Python script that performs a security scan using modern best practices.\n"
                        "Task description: {user_input}\n"
                        "Explain your implementation approach."
                    ),
                }
        self.default_prompts = StarkPromptEngine._PROMPT_CACHE

    def build_prompt(self, user_query: Any, context: dict = None) -> str:
        """
        Build a prompt for a given user input (dict or str) using default prompts.
        
        This method:
        1. Normalizes the user query to a dictionary
        2. Selects the appropriate prompt template based on action type
        3. Formats the template with user data and targets
        4. Returns a complete prompt ready for the LLM
        
        Args:
            user_query: Raw user input (str or dict)
            context: Optional additional context (session history, etc.)
            
        Returns:
            Formatted prompt string ready for LLM
        """
        # Step 1: Normalize user_query to dict
        if isinstance(user_query, dict):
            cmd = user_query
        else:
            try:
                cmd = json.loads(user_query)
            except Exception:
                try:
                    cmd = json.loads(process_user_input(user_query, output_context="json"))
                except Exception:
                    cmd = {"raw": str(user_query), "action": "general"}

        action = cmd.get("action", "general")
        template = self.default_prompts.get(action, self.default_prompts["general"])

        # Step 2: Prepare format map, starting from default args
        fmt_map = copy.deepcopy(DEFAULT_FORMAT_ARGS)

        fmt_map.update({
            "user_input": cmd.get("raw", fmt_map["user_input"]),
            "allowed_targets": ", ".join(
                str(t["value"]) if isinstance(t, dict) and "value" in t else str(t)
                for t in cmd.get("sanitized_targets", [])
            ) or fmt_map["allowed_targets"],
            "error_response": '{"error":"target not allowed"}',
            "example_json": '{}'
        })

        if context and isinstance(context, dict):
            fmt_map.update(context)

        ports = cmd.get("ports")
        if ports:
            fmt_map["ports"] = ", ".join(str(p) for p in ports)

        # Step 3: Build prompt
        if isinstance(template, list):
            template = "\n".join(str(line) for line in template)

        # Use standard format() - JSON templates are already escaped with {{ and }}
        prompt = template.format(**fmt_map)
        return prompt


# Example usage
if __name__ == "__main__":
    raw_input = input("Enter your command: ")
    # Produce a structured command and build prompt from it
    cmd_json = process_user_input(raw_input, output_context="json")
    builder = StarkPromptEngine()
    prompt = builder.build_prompt(cmd_json)
    
    print("\nGenerated LLM prompt:\n")
    print(prompt)
        