"""
VT ARC API Client - Main unified interface
Professional implementation with all features integrated
"""

import logging
from typing import Dict, Any, Optional, List, Union
from pathlib import Path

from config import APIConfig, Model, ReasoningEffort, PromptInjectionConfig
from core.base_client import BaseAPIClient
from core.chat_client import ChatClient, ChatMessage, Conversation
from core.document_client import DocumentClient, UploadedFile
from core.image_client import ImageClient, GeneratedImage
from utils.logger import setup_logger
from exceptions import VTARCAPIException


logger = logging.getLogger(__name__)


class VTARCClient:
    """
    Unified VT ARC API Client
    Professional implementation with all features integrated
    """

    def __init__(self,
                 api_keys: Optional[List[str]] = None,
                 config: Optional[APIConfig] = None,
                 prompt_injection: Optional[PromptInjectionConfig] = None,
                 log_level: str = "INFO",
                 log_file: Optional[str] = None):
        """
        Initialize VT ARC API Client

        Args:
            api_keys: List of API keys (up to 5)
            config: Custom configuration
            prompt_injection: Prompt injection configuration
            log_level: Logging level
            log_file: Log file path
        """
        # Setup logging
        setup_logger(
            name="vt_arc_api",
            level=log_level,
            log_file=log_file,
            enable_color=True
        )

        # Initialize configuration
        if config:
            self.config = config
        else:
            self.config = APIConfig(api_keys=api_keys or [])

        # Initialize prompt injection
        self.prompt_injection = prompt_injection or PromptInjectionConfig(enabled=False)

        # Initialize base client
        self.base_client = BaseAPIClient(self.config)

        # Initialize specialized clients
        self.chat = ChatClient(self.base_client, self.prompt_injection)
        self.documents = DocumentClient(self.base_client)
        self.images = ImageClient(self.base_client)

        logger.info(f"VT ARC API Client initialized with {len(self.config.api_keys)} API key(s)")

    # ============== Chat Methods ==============

    def chat_completion(self,
                       prompt: str,
                       model: Optional[Union[Model, str]] = None,
                       system_message: Optional[str] = None,
                       temperature: Optional[float] = None,
                       max_tokens: Optional[int] = None,
                       stream: bool = False,
                       web_search: bool = False,
                       reasoning_effort: Optional[Union[ReasoningEffort, str]] = None,
                       inject_prompt: bool = True,
                       template_name: Optional[str] = None) -> Union[str, Dict[str, Any]]:
        """
        Simple chat completion

        Args:
            prompt: User prompt
            model: Model to use
            system_message: System message
            temperature: Sampling temperature
            max_tokens: Max tokens to generate
            stream: Enable streaming
            web_search: Enable web search
            reasoning_effort: Reasoning effort for gpt-oss-120b
            inject_prompt: Apply prompt injection
            template_name: Prompt template name

        Returns:
            Response text or full response dict if streaming
        """
        if stream:
            return self.chat.create_completion(
                messages=[
                    ChatMessage("system", system_message) if system_message else None,
                    ChatMessage("user", prompt)
                ],
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
                reasoning_effort=reasoning_effort,
                enable_web_search=web_search,
                inject_prompt=inject_prompt,
                template_name=template_name
            )
        else:
            return self.chat.create_simple_completion(
                prompt=prompt,
                model=model,
                system_message=system_message,
                temperature=temperature,
                max_tokens=max_tokens,
                reasoning_effort=reasoning_effort,
                enable_web_search=web_search,
                inject_prompt=inject_prompt,
                template_name=template_name
            )

    def create_conversation(self,
                          system_message: Optional[str] = None) -> Conversation:
        """
        Create a conversation manager

        Args:
            system_message: Initial system message

        Returns:
            Conversation manager
        """
        return self.chat.create_conversation(system_message)

    # ============== Document/RAG Methods ==============

    def upload_document(self,
                       file_path: Union[str, Path]) -> UploadedFile:
        """
        Upload a document

        Args:
            file_path: Path to document

        Returns:
            UploadedFile object
        """
        return self.documents.upload_file(file_path)

    def query_documents(self,
                       query: str,
                       file_paths: Optional[List[Union[str, Path]]] = None,
                       file_ids: Optional[List[str]] = None,
                       model: Optional[Union[Model, str]] = None) -> str:
        """
        Query documents using RAG

        Args:
            query: Query text
            file_paths: Document paths to upload and query
            file_ids: Already uploaded file IDs
            model: Model to use

        Returns:
            Response text
        """
        uploaded_files = []

        # Upload new files if provided
        if file_paths:
            for path in file_paths:
                uploaded = self.documents.upload_file(path)
                uploaded_files.append(uploaded)

        return self.documents.query_with_documents(
            query=query,
            uploaded_files=uploaded_files if uploaded_files else None,
            file_ids=file_ids,
            model=model
        )

    def summarize_document(self,
                         file_path: Union[str, Path],
                         summary_type: str = "brief") -> str:
        """
        Generate document summary

        Args:
            file_path: Path to document
            summary_type: Type of summary ("brief", "detailed", "bullets")

        Returns:
            Document summary
        """
        return self.documents.summarize_document(file_path, summary_type)

    # ============== Image Methods ==============

    def generate_image(self,
                      prompt: str,
                      size: str = "512x512",
                      save_path: Optional[Union[str, Path]] = None) -> GeneratedImage:
        """
        Generate an image

        Args:
            prompt: Text prompt
            size: Image size
            save_path: Path to save image

        Returns:
            GeneratedImage object
        """
        return self.images.generate_image(prompt, size, save_path=save_path)

    def analyze_image(self,
                     image_path: Union[str, Path],
                     prompt: str = "Describe this image",
                     detailed: bool = False) -> str:
        """
        Analyze an image

        Args:
            image_path: Path to image
            prompt: Analysis prompt
            detailed: Request detailed analysis

        Returns:
            Image analysis
        """
        return self.images.analyze_image(image_path, prompt, detailed=detailed)

    def extract_text_from_image(self,
                              image_path: Union[str, Path],
                              language: str = "English") -> str:
        """
        Extract text from image (OCR)

        Args:
            image_path: Path to image
            language: Expected language

        Returns:
            Extracted text
        """
        return self.images.extract_text_from_image(image_path, language)

    # ============== Advanced Methods ==============

    def multimodal_query(self,
                        text_prompt: str,
                        image_paths: Optional[List[Union[str, Path]]] = None,
                        document_paths: Optional[List[Union[str, Path]]] = None,
                        web_search: bool = False,
                        model: Optional[Union[Model, str]] = None) -> str:
        """
        Perform a multimodal query with text, images, and documents

        Args:
            text_prompt: Text prompt
            image_paths: Image paths for analysis
            document_paths: Document paths for RAG
            web_search: Enable web search
            model: Model to use

        Returns:
            Response text
        """
        # Use vision model if images provided
        if image_paths and model is None:
            model = Model.GLM_4_5V_AWQ

        # Upload documents if provided
        file_ids = []
        if document_paths:
            for path in document_paths:
                uploaded = self.documents.upload_file(path)
                file_ids.append(uploaded.file_id)

        # Build multimodal message if images provided
        if image_paths:
            message_content = [{"type": "text", "text": text_prompt}]

            for image_path in image_paths:
                image_path = Path(image_path)
                image_base64 = self.images._encode_image(image_path)
                message_content.append({
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/{image_path.suffix[1:]};base64,{image_base64}"
                    }
                })

            messages = [ChatMessage("user", message_content)]
        else:
            messages = [ChatMessage("user", text_prompt)]

        # Create completion with all features
        response = self.chat.create_completion(
            messages=messages,
            model=model,
            enable_web_search=web_search,
            files=[{"type": "file", "id": fid} for fid in file_ids] if file_ids else None
        )

        # Extract content
        if isinstance(response, dict):
            choices = response.get('choices', [])
            if choices:
                return choices[0].get('message', {}).get('content', '')

        return ''

    # ============== Prompt Injection Methods ==============

    def add_prompt_template(self,
                          name: str,
                          template: str) -> None:
        """
        Add a custom prompt template

        Args:
            name: Template name
            template: Template content
        """
        self.prompt_injection.templates[name] = template

    def set_system_instructions(self,
                               instructions: str,
                               role: Optional[str] = None) -> None:
        """
        Set global system instructions

        Args:
            instructions: System instructions
            role: Optional role description
        """
        self.prompt_injection.system_instructions = instructions
        if role:
            self.prompt_injection.system_role = role
        self.prompt_injection.enabled = True

    def set_context_injection(self,
                            prefix: Optional[str] = None,
                            suffix: Optional[str] = None) -> None:
        """
        Set context injection for user messages

        Args:
            prefix: Prefix for user messages
            suffix: Suffix for user messages
        """
        if prefix:
            self.prompt_injection.context_prefix = prefix
        if suffix:
            self.prompt_injection.context_suffix = suffix
        self.prompt_injection.enabled = True

    # ============== Utility Methods ==============

    def test_connection(self) -> bool:
        """Test API connection"""
        return self.base_client.test_connection()

    def get_rate_limit_status(self) -> Dict[str, Dict[str, int]]:
        """Get rate limit status for all API keys"""
        return self.base_client.get_remaining_requests()

    def reset_rate_limits(self) -> None:
        """Reset all rate limits"""
        self.base_client.reset_rate_limits()

    def get_models(self) -> List[str]:
        """Get list of available models"""
        try:
            response = self.base_client.get('/models')
            data = self.base_client.parse_response(response)
            return [model.get('id') for model in data.get('data', [])]
        except Exception as e:
            logger.error(f"Failed to get models: {e}")
            return [m.value for m in Model]

    def close(self) -> None:
        """Close the client and cleanup resources"""
        self.base_client.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Convenience function for quick usage
def create_client(api_keys: Optional[List[str]] = None,
                 **kwargs) -> VTARCClient:
    """
    Create a VT ARC API client

    Args:
        api_keys: List of API keys
        **kwargs: Additional configuration

    Returns:
        Configured VTARCClient
    """
    return VTARCClient(api_keys=api_keys, **kwargs)