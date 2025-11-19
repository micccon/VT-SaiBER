"""
Document and RAG client for VT ARC API
Handles file uploads and retrieval-augmented generation
"""

import os
import logging
from typing import Dict, Any, Optional, List, Union, BinaryIO
from pathlib import Path
from dataclasses import dataclass

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.base_client import BaseAPIClient
from core.chat_client import ChatClient, ChatMessage
from exceptions import FileUploadError, InvalidRequestError


logger = logging.getLogger(__name__)


@dataclass
class UploadedFile:
    """Represents an uploaded file"""
    file_id: str
    filename: str
    size: Optional[int] = None
    upload_time: Optional[str] = None

    def to_rag_format(self) -> Dict[str, str]:
        """Convert to format for RAG requests"""
        return {
            "type": "file",
            "id": self.file_id
        }


class DocumentClient:
    """
    Client for document operations and RAG
    """

    def __init__(self, base_client: Optional[BaseAPIClient] = None):
        """
        Initialize document client

        Args:
            base_client: Base API client (creates new if not provided)
        """
        self.client = base_client or BaseAPIClient()
        self.chat_client = ChatClient(base_client=self.client)
        self.uploaded_files: Dict[str, UploadedFile] = {}

    def upload_file(self,
                   file_path: Union[str, Path],
                   validate_extension: bool = True) -> UploadedFile:
        """
        Upload a file to the API

        Args:
            file_path: Path to file to upload
            validate_extension: Check if file extension is allowed

        Returns:
            UploadedFile object with file details

        Raises:
            FileUploadError if upload fails
        """
        file_path = Path(file_path)

        # Validate file exists
        if not file_path.exists():
            raise FileUploadError(f"File not found: {file_path}")

        # Validate file size
        file_size = file_path.stat().st_size
        max_size = self.client.config.max_file_size_mb * 1024 * 1024
        if file_size > max_size:
            raise FileUploadError(
                f"File too large: {file_size / 1024 / 1024:.2f}MB "
                f"(max: {self.client.config.max_file_size_mb}MB)"
            )

        # Validate extension
        if validate_extension:
            if file_path.suffix.lower() not in self.client.config.allowed_file_extensions:
                raise FileUploadError(
                    f"File type not allowed: {file_path.suffix}. "
                    f"Allowed types: {', '.join(self.client.config.allowed_file_extensions)}"
                )

        logger.info(f"Uploading file: {file_path.name} ({file_size / 1024:.2f}KB)")

        try:
            # Prepare file for upload
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f, 'application/octet-stream')}

                # Upload file
                response = self.client.post(
                    '/files/',
                    files=files,
                    timeout=self.client.config.upload_timeout
                )

            # Parse response
            data = self.client.parse_response(response)

            # Create UploadedFile object
            uploaded_file = UploadedFile(
                file_id=data.get('id'),
                filename=file_path.name,
                size=file_size,
                upload_time=data.get('created_at')
            )

            # Store in cache
            self.uploaded_files[uploaded_file.file_id] = uploaded_file

            logger.info(f"Successfully uploaded file. ID: {uploaded_file.file_id}")

            return uploaded_file

        except Exception as e:
            raise FileUploadError(f"Failed to upload file: {e}")

    def upload_from_bytes(self,
                         data: bytes,
                         filename: str) -> UploadedFile:
        """
        Upload file from bytes

        Args:
            data: File data as bytes
            filename: Name for the file

        Returns:
            UploadedFile object
        """
        # Check size
        max_size = self.client.config.max_file_size_mb * 1024 * 1024
        if len(data) > max_size:
            raise FileUploadError(
                f"Data too large: {len(data) / 1024 / 1024:.2f}MB "
                f"(max: {self.client.config.max_file_size_mb}MB)"
            )

        logger.info(f"Uploading bytes as: {filename} ({len(data) / 1024:.2f}KB)")

        try:
            files = {'file': (filename, data, 'application/octet-stream')}

            response = self.client.post(
                '/files/',
                files=files,
                timeout=self.client.config.upload_timeout
            )

            data_dict = self.client.parse_response(response)

            uploaded_file = UploadedFile(
                file_id=data_dict.get('id'),
                filename=filename,
                size=len(data),
                upload_time=data_dict.get('created_at')
            )

            self.uploaded_files[uploaded_file.file_id] = uploaded_file

            logger.info(f"Successfully uploaded. ID: {uploaded_file.file_id}")

            return uploaded_file

        except Exception as e:
            raise FileUploadError(f"Failed to upload data: {e}")

    def upload_multiple_files(self,
                            file_paths: List[Union[str, Path]],
                            validate_extension: bool = True) -> List[UploadedFile]:
        """
        Upload multiple files

        Args:
            file_paths: List of file paths
            validate_extension: Check if file extensions are allowed

        Returns:
            List of UploadedFile objects
        """
        uploaded = []
        failed = []

        for file_path in file_paths:
            try:
                uploaded_file = self.upload_file(file_path, validate_extension)
                uploaded.append(uploaded_file)
            except Exception as e:
                logger.error(f"Failed to upload {file_path}: {e}")
                failed.append((file_path, str(e)))

        if failed:
            logger.warning(f"Failed to upload {len(failed)} file(s)")

        return uploaded

    def query_with_documents(self,
                            query: str,
                            file_ids: Optional[List[str]] = None,
                            uploaded_files: Optional[List[UploadedFile]] = None,
                            model: Optional[str] = None,
                            system_message: Optional[str] = None,
                            **kwargs) -> str:
        """
        Query using RAG with documents

        Args:
            query: Query text
            file_ids: List of file IDs to use
            uploaded_files: List of UploadedFile objects
            model: Model to use
            system_message: Optional system message
            **kwargs: Additional parameters for chat completion

        Returns:
            Response text
        """
        # Build files list
        files = []

        if file_ids:
            for file_id in file_ids:
                files.append({"type": "file", "id": file_id})

        if uploaded_files:
            for uploaded_file in uploaded_files:
                files.append(uploaded_file.to_rag_format())

        if not files:
            logger.warning("No files provided for RAG query")

        # Build messages
        messages = []
        if system_message:
            messages.append(ChatMessage("system", system_message))
        messages.append(ChatMessage("user", query))

        # Make request
        response = self.chat_client.create_completion(
            messages=messages,
            model=model,
            files=files if files else None,
            **kwargs
        )

        # Extract content
        if isinstance(response, dict):
            choices = response.get('choices', [])
            if choices:
                return choices[0].get('message', {}).get('content', '')

        return ''

    def analyze_document(self,
                        file_path: Union[str, Path],
                        analysis_prompt: str,
                        model: Optional[str] = None,
                        upload_first: bool = True,
                        **kwargs) -> Dict[str, Any]:
        """
        Analyze a document with custom prompt

        Args:
            file_path: Path to document
            analysis_prompt: Prompt for analysis
            model: Model to use
            upload_first: Upload file first (False if already uploaded)
            **kwargs: Additional parameters

        Returns:
            Analysis results
        """
        if upload_first:
            uploaded_file = self.upload_file(file_path)
            file_id = uploaded_file.file_id
        else:
            # Assume file_path is actually a file_id
            file_id = str(file_path)

        # Query with document
        result = self.query_with_documents(
            query=analysis_prompt,
            file_ids=[file_id],
            model=model,
            **kwargs
        )

        return {
            'file_id': file_id,
            'analysis': result,
            'prompt': analysis_prompt
        }

    def summarize_document(self,
                          file_path: Union[str, Path],
                          summary_type: str = "brief",
                          model: Optional[str] = None,
                          **kwargs) -> str:
        """
        Generate document summary

        Args:
            file_path: Path to document
            summary_type: Type of summary ("brief", "detailed", "bullets")
            model: Model to use
            **kwargs: Additional parameters

        Returns:
            Document summary
        """
        prompts = {
            "brief": "Create a brief 2-3 sentence summary of this document.",
            "detailed": "Create a detailed summary of this document, covering all main points.",
            "bullets": "Create a bullet-point summary of the key points in this document."
        }

        prompt = prompts.get(summary_type, prompts["brief"])

        result = self.analyze_document(
            file_path=file_path,
            analysis_prompt=prompt,
            model=model,
            **kwargs
        )

        return result['analysis']

    def extract_information(self,
                          file_path: Union[str, Path],
                          extraction_template: Dict[str, str],
                          model: Optional[str] = None,
                          **kwargs) -> Dict[str, Any]:
        """
        Extract structured information from document

        Args:
            file_path: Path to document
            extraction_template: Template defining what to extract
            model: Model to use
            **kwargs: Additional parameters

        Returns:
            Extracted information
        """
        # Build extraction prompt
        prompt = "Extract the following information from the document:\n\n"
        for key, description in extraction_template.items():
            prompt += f"- {key}: {description}\n"

        prompt += "\nProvide the information in a structured format."

        result = self.analyze_document(
            file_path=file_path,
            analysis_prompt=prompt,
            model=model,
            **kwargs
        )

        return {
            'raw_response': result['analysis'],
            'template': extraction_template
        }

    def compare_documents(self,
                        file_paths: List[Union[str, Path]],
                        comparison_aspects: Optional[List[str]] = None,
                        model: Optional[str] = None,
                        **kwargs) -> str:
        """
        Compare multiple documents

        Args:
            file_paths: List of document paths
            comparison_aspects: Specific aspects to compare
            model: Model to use
            **kwargs: Additional parameters

        Returns:
            Comparison results
        """
        # Upload all files
        uploaded_files = self.upload_multiple_files(file_paths)

        # Build comparison prompt
        prompt = f"Compare these {len(uploaded_files)} documents"

        if comparison_aspects:
            prompt += " focusing on the following aspects:\n"
            for aspect in comparison_aspects:
                prompt += f"- {aspect}\n"
        else:
            prompt += " and highlight key similarities and differences."

        # Query with all documents
        result = self.query_with_documents(
            query=prompt,
            uploaded_files=uploaded_files,
            model=model,
            **kwargs
        )

        return result

    def get_uploaded_files(self) -> List[UploadedFile]:
        """Get list of uploaded files in this session"""
        return list(self.uploaded_files.values())

    def clear_uploaded_files(self) -> None:
        """Clear the uploaded files cache"""
        self.uploaded_files.clear()