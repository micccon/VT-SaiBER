"""
Chat completions client for VT ARC API
Handles chat interactions, streaming, and advanced features
"""

import json
import logging
from typing import Dict, Any, Optional, List, Generator, Union
from dataclasses import dataclass, asdict

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.base_client import BaseAPIClient
from config import Model, ReasoningEffort, PromptInjectionConfig
from exceptions import InvalidRequestError, VTARCAPIException


logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    """Represents a chat message"""
    role: str  # "system", "user", "assistant"
    content: Union[str, List[Dict[str, Any]]]  # Text or multimodal content

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API"""
        return {
            "role": self.role,
            "content": self.content
        }


@dataclass
class ChatCompletionRequest:
    """Chat completion request parameters"""
    model: str
    messages: List[Dict[str, Any]]
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    top_p: Optional[float] = None
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    stop: Optional[Union[str, List[str]]] = None
    stream: bool = False
    reasoning_effort: Optional[str] = None  # For gpt-oss-120b
    tool_ids: Optional[List[str]] = None  # For web search
    files: Optional[List[Dict[str, str]]] = None  # For RAG

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, removing None values"""
        data = {}
        for key, value in asdict(self).items():
            if value is not None:
                data[key] = value
        return data


class ChatClient:
    """
    Client for chat completions with advanced features
    """

    def __init__(self,
                 base_client: Optional[BaseAPIClient] = None,
                 prompt_injection: Optional[PromptInjectionConfig] = None):
        """
        Initialize chat client

        Args:
            base_client: Base API client (creates new if not provided)
            prompt_injection: Prompt injection configuration
        """
        self.client = base_client or BaseAPIClient()
        self.prompt_injection = prompt_injection or PromptInjectionConfig(enabled=False)

    def create_completion(self,
                         messages: List[Union[ChatMessage, Dict[str, Any]]],
                         model: Optional[Union[Model, str]] = None,
                         temperature: Optional[float] = None,
                         max_tokens: Optional[int] = None,
                         top_p: Optional[float] = None,
                         frequency_penalty: Optional[float] = None,
                         presence_penalty: Optional[float] = None,
                         stop: Optional[Union[str, List[str]]] = None,
                         stream: bool = False,
                         reasoning_effort: Optional[Union[ReasoningEffort, str]] = None,
                         enable_web_search: bool = False,
                         files: Optional[List[Dict[str, str]]] = None,
                         inject_prompt: bool = True,
                         template_name: Optional[str] = None) -> Union[Dict[str, Any], Generator]:
        """
        Create chat completion

        Args:
            messages: List of messages (ChatMessage or dict)
            model: Model to use
            temperature: Sampling temperature (0-2)
            max_tokens: Maximum tokens to generate
            top_p: Top-p sampling
            frequency_penalty: Frequency penalty (-2 to 2)
            presence_penalty: Presence penalty (-2 to 2)
            stop: Stop sequences
            stream: Enable streaming response
            reasoning_effort: Reasoning effort for gpt-oss-120b
            enable_web_search: Enable web search tool
            files: Files for RAG (list of {"type": "file", "id": "file_id"})
            inject_prompt: Apply prompt injection
            template_name: Prompt injection template name

        Returns:
            Completion response (dict) or stream generator
        """
        # Convert messages to dict format
        message_dicts = []
        for msg in messages:
            if isinstance(msg, ChatMessage):
                message_dicts.append(msg.to_dict())
            elif isinstance(msg, dict):
                message_dicts.append(msg)
            else:
                raise InvalidRequestError(f"Invalid message type: {type(msg)}")

        # Apply prompt injection if enabled
        if inject_prompt and self.prompt_injection.enabled:
            message_dicts = self.prompt_injection.apply_injection(
                message_dicts,
                template_name=template_name
            )

        # Determine model
        if model is None:
            model = self.client.config.default_model
        if isinstance(model, Model):
            model = model.value

        # Build request
        request = ChatCompletionRequest(
            model=model,
            messages=message_dicts,
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=top_p,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty,
            stop=stop,
            stream=stream
        )

        # Add reasoning effort for gpt-oss-120b
        if model == Model.GPT_OSS_120B.value and reasoning_effort:
            if isinstance(reasoning_effort, ReasoningEffort):
                reasoning_effort = reasoning_effort.value
            request.reasoning_effort = reasoning_effort

        # Add web search if enabled
        if enable_web_search:
            request.tool_ids = ["server:websearch"]

        # Add files for RAG
        if files:
            request.files = files

        # Convert to dict
        request_data = request.to_dict()

        logger.debug(f"Creating chat completion with model: {model}")

        # Make request
        if stream:
            return self._stream_completion(request_data)
        else:
            response = self.client.post(
                '/chat/completions',
                json_data=request_data
            )
            return self.client.parse_response(response)

    def _stream_completion(self, request_data: Dict[str, Any]) -> Generator:
        """
        Stream chat completion

        Args:
            request_data: Request data

        Yields:
            Streaming response chunks
        """
        request_data['stream'] = True

        response = self.client.post(
            '/chat/completions',
            json_data=request_data,
            stream=True
        )

        # Process streaming response
        for line in response.iter_lines():
            if line:
                line = line.decode('utf-8')
                if line.startswith('data: '):
                    data = line[6:]
                    if data == '[DONE]':
                        break
                    try:
                        chunk = json.loads(data)
                        yield chunk
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse streaming chunk: {data}")

    def create_simple_completion(self,
                                prompt: str,
                                model: Optional[Union[Model, str]] = None,
                                system_message: Optional[str] = None,
                                **kwargs) -> str:
        """
        Simple interface for single-turn completion

        Args:
            prompt: User prompt
            model: Model to use
            system_message: Optional system message
            **kwargs: Additional parameters for create_completion

        Returns:
            Generated text content
        """
        messages = []

        if system_message:
            messages.append(ChatMessage("system", system_message))

        messages.append(ChatMessage("user", prompt))

        response = self.create_completion(messages, model=model, **kwargs)

        # Extract content from response
        if isinstance(response, dict):
            choices = response.get('choices', [])
            if choices:
                return choices[0].get('message', {}).get('content', '')

        return ''

    def create_conversation(self,
                          initial_system: Optional[str] = None) -> 'Conversation':
        """
        Create a conversation manager

        Args:
            initial_system: Initial system message

        Returns:
            Conversation manager
        """
        return Conversation(self, initial_system)


class Conversation:
    """
    Manages a multi-turn conversation
    """

    def __init__(self,
                 chat_client: ChatClient,
                 initial_system: Optional[str] = None):
        """
        Initialize conversation

        Args:
            chat_client: Chat client to use
            initial_system: Initial system message
        """
        self.client = chat_client
        self.messages: List[ChatMessage] = []

        if initial_system:
            self.add_system_message(initial_system)

    def add_system_message(self, content: str) -> 'Conversation':
        """Add system message"""
        self.messages.append(ChatMessage("system", content))
        return self

    def add_user_message(self, content: Union[str, List[Dict[str, Any]]]) -> 'Conversation':
        """Add user message"""
        self.messages.append(ChatMessage("user", content))
        return self

    def add_assistant_message(self, content: str) -> 'Conversation':
        """Add assistant message"""
        self.messages.append(ChatMessage("assistant", content))
        return self

    def add_message(self, role: str, content: Union[str, List[Dict[str, Any]]]) -> 'Conversation':
        """Add message with specified role"""
        self.messages.append(ChatMessage(role, content))
        return self

    def get_response(self,
                     user_input: Optional[str] = None,
                     **kwargs) -> str:
        """
        Get response from assistant

        Args:
            user_input: Optional user input to add before getting response
            **kwargs: Parameters for create_completion

        Returns:
            Assistant response
        """
        if user_input:
            self.add_user_message(user_input)

        # Get completion
        response = self.client.create_completion(self.messages, **kwargs)

        # Extract and store response
        if isinstance(response, dict):
            choices = response.get('choices', [])
            if choices:
                content = choices[0].get('message', {}).get('content', '')
                self.add_assistant_message(content)
                return content

        return ''

    def stream_response(self,
                       user_input: Optional[str] = None,
                       **kwargs) -> Generator:
        """
        Stream response from assistant

        Args:
            user_input: Optional user input to add
            **kwargs: Parameters for create_completion

        Yields:
            Response chunks
        """
        if user_input:
            self.add_user_message(user_input)

        # Stream completion
        full_response = ""
        for chunk in self.client.create_completion(self.messages, stream=True, **kwargs):
            if isinstance(chunk, dict):
                choices = chunk.get('choices', [])
                if choices:
                    delta = choices[0].get('delta', {})
                    content = delta.get('content', '')
                    if content:
                        full_response += content
                        yield content

        # Add complete response to conversation
        if full_response:
            self.add_assistant_message(full_response)

    def clear(self) -> 'Conversation':
        """Clear conversation history"""
        self.messages.clear()
        return self

    def get_history(self) -> List[Dict[str, Any]]:
        """Get conversation history as list of dicts"""
        return [msg.to_dict() for msg in self.messages]

    def save(self, filepath: str) -> None:
        """Save conversation to file"""
        import json
        with open(filepath, 'w') as f:
            json.dump(self.get_history(), f, indent=2)

    def load(self, filepath: str) -> 'Conversation':
        """Load conversation from file"""
        import json
        with open(filepath, 'r') as f:
            history = json.load(f)

        self.messages.clear()
        for msg in history:
            self.messages.append(ChatMessage(msg['role'], msg['content']))

        return self