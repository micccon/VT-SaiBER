"""
Prompt Engineer ("Tony Stark")

This module is responsible for constructing the precise prompts that are
sent to the LLM. It combines the user's query with system instructions,
the agent registry, and any relevant context or memory.
"""
import json

class StarkPromptEngine:

    def __init__(self, agent_registry_path: str):
        ...