"""
LLM Manager ("Jarvis")

This module is responsible for all interactions with the external
Large Language Model (e.g., OpenAI, Google Gemini). It sends prompts
and parses the structured output.
"""
# import schemas here

class JarvisLLM:
    """
        Handles all communication with configured LLM
    """
    
    # need at least an api_key, model, config from main folder, and baseurl
    # Example
    def __init__(self, llm_config: dict):
        self.config = llm_config
        self.api_key = self.config.get("api_key", "DUMMY_KEY_FOR_TESTING")
        self.model_name = self.config.get("model_name")
        self.base_url = "https://api.openai.com/v1" # Example for OpenAI
        print(f"LLMManager initialized for model: {self.model_name}")
