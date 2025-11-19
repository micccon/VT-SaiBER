"""
Configuration module for VT ARC API Client
Centralized configuration management for the API client
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import os


class Model(Enum):
    """Available models on VT ARC platform"""
    GLM_4_5_AIR = "GLM-4.5-Air"
    GLM_4_5V_AWQ = "GLM-4.5V-AWQ"  # Vision capabilities
    GPT_OSS_120B = "gpt-oss-120b"


class ReasoningEffort(Enum):
    """Reasoning effort levels for gpt-oss-120b"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class RateLimits:
    """Rate limiting configuration"""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_3_hours: int = 2000

    # Internal tracking
    minute_window: int = 60
    hour_window: int = 3600
    three_hour_window: int = 10800


@dataclass
class APIConfig:
    """Main API configuration"""
    base_url: str = "https://llm-api.arc.vt.edu/api/v1"
    api_keys: List[str] = field(default_factory=list)
    default_model: Model = Model.GLM_4_5_AIR
    default_reasoning_effort: ReasoningEffort = ReasoningEffort.MEDIUM

    # Timeouts
    request_timeout: int = 30
    upload_timeout: int = 60

    # Rate limiting
    rate_limits: RateLimits = field(default_factory=RateLimits)
    enable_rate_limiting: bool = True

    # Retry configuration
    max_retries: int = 3
    retry_delay: float = 1.0
    exponential_backoff: bool = True

    # Logging
    enable_logging: bool = True
    log_level: str = "INFO"
    log_file: Optional[str] = "vt_arc_api.log"

    # Prompt injection
    system_prompt_prefix: Optional[str] = None
    system_prompt_suffix: Optional[str] = None
    user_prompt_prefix: Optional[str] = None
    user_prompt_suffix: Optional[str] = None

    # File handling
    max_file_size_mb: int = 100
    allowed_file_extensions: List[str] = field(default_factory=lambda: [
        ".pdf", ".txt", ".docx", ".doc", ".csv", ".json", ".md", ".rtf"
    ])

    # Image generation
    default_image_size: str = "512x512"
    supported_image_sizes: List[str] = field(default_factory=lambda: [
        "256x256", "512x512", "1024x1024"
    ])

    def __post_init__(self):
        """Validate configuration after initialization"""
        if not self.api_keys:
            # Try to load from environment variables
            env_keys = []
            for i in range(1, 6):  # Support up to 5 API keys
                key = os.getenv(f"VT_ARC_API_KEY_{i}")
                if key:
                    env_keys.append(key)

            # Also check for single key
            single_key = os.getenv("VT_ARC_API_KEY")
            if single_key and single_key not in env_keys:
                env_keys.insert(0, single_key)

            if env_keys:
                self.api_keys = env_keys
            else:
                raise ValueError("No API keys provided. Set VT_ARC_API_KEY environment variable or pass api_keys parameter")

        # Validate API keys format
        for key in self.api_keys:
            if not key.startswith("sk-"):
                raise ValueError(f"Invalid API key format. Keys must start with 'sk-'")

        # Ensure we don't exceed 5 API keys
        if len(self.api_keys) > 5:
            print(f"Warning: More than 5 API keys provided. Using only the first 5.")
            self.api_keys = self.api_keys[:5]


@dataclass
class PromptInjectionConfig:
    """Configuration for prompt injection system"""
    enabled: bool = True

    # System-level injections
    system_role: Optional[str] = None
    system_instructions: Optional[str] = None

    # Contextual injections
    context_prefix: Optional[str] = None
    context_suffix: Optional[str] = None

    # Safety injections
    safety_instructions: Optional[str] = None

    # Custom templates
    templates: Dict[str, str] = field(default_factory=dict)

    def apply_injection(self, messages: List[Dict[str, str]],
                       template_name: Optional[str] = None) -> List[Dict[str, str]]:
        """Apply prompt injections to messages"""
        if not self.enabled:
            return messages

        injected_messages = messages.copy()

        # Add system message if configured
        if self.system_role or self.system_instructions:
            system_msg = {
                "role": "system",
                "content": self.system_instructions or ""
            }
            if self.system_role:
                system_msg["content"] = f"{self.system_role}\n\n{system_msg['content']}"

            # Check if system message already exists
            if injected_messages and injected_messages[0].get("role") == "system":
                # Merge with existing system message
                injected_messages[0]["content"] = f"{system_msg['content']}\n\n{injected_messages[0]['content']}"
            else:
                injected_messages.insert(0, system_msg)

        # Apply template if specified
        if template_name and template_name in self.templates:
            template = self.templates[template_name]
            if injected_messages and injected_messages[0].get("role") == "system":
                injected_messages[0]["content"] = f"{injected_messages[0]['content']}\n\n{template}"
            else:
                injected_messages.insert(0, {"role": "system", "content": template})

        # Apply context injections to user messages
        for i, msg in enumerate(injected_messages):
            if msg.get("role") == "user":
                content = msg["content"]
                if self.context_prefix:
                    content = f"{self.context_prefix}\n{content}"
                if self.context_suffix:
                    content = f"{content}\n{self.context_suffix}"
                injected_messages[i]["content"] = content

        # Add safety instructions if configured
        if self.safety_instructions:
            injected_messages.append({
                "role": "system",
                "content": self.safety_instructions
            })

        return injected_messages