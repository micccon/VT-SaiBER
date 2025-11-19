"""
VT ARC API Client
Professional Python client for Virginia Tech ARC LLM API
"""

__version__ = "1.0.0"
__author__ = "Senior Developer"

from .vt_arc_api import VTARCClient, create_client
from .config import APIConfig, Model, ReasoningEffort, PromptInjectionConfig
from .core.chat_client import ChatClient, ChatMessage, Conversation
from .core.document_client import DocumentClient, UploadedFile
from .core.image_client import ImageClient, GeneratedImage
from .exceptions import (
    VTARCAPIException,
    AuthenticationError,
    RateLimitError,
    APIKeyExhaustedError,
    FileUploadError,
    ModelNotAvailableError,
    InvalidRequestError,
    NetworkError,
    TimeoutError,
    ResponseParsingError
)

__all__ = [
    # Main client
    'VTARCClient',
    'create_client',

    # Configuration
    'APIConfig',
    'Model',
    'ReasoningEffort',
    'PromptInjectionConfig',

    # Chat
    'ChatClient',
    'ChatMessage',
    'Conversation',

    # Documents
    'DocumentClient',
    'UploadedFile',

    # Images
    'ImageClient',
    'GeneratedImage',

    # Exceptions
    'VTARCAPIException',
    'AuthenticationError',
    'RateLimitError',
    'APIKeyExhaustedError',
    'FileUploadError',
    'ModelNotAvailableError',
    'InvalidRequestError',
    'NetworkError',
    'TimeoutError',
    'ResponseParsingError'
]