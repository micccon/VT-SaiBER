"""
Image generation and analysis client for VT ARC API
Handles image generation, image-to-text, and vision capabilities
"""

import base64
import logging
from typing import Dict, Any, Optional, List, Union, Tuple
from pathlib import Path
from io import BytesIO
from urllib.parse import urlparse
from dataclasses import dataclass

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.base_client import BaseAPIClient
from core.chat_client import ChatClient, ChatMessage
from config import Model
from exceptions import InvalidRequestError, VTARCAPIException


logger = logging.getLogger(__name__)


@dataclass
class GeneratedImage:
    """Represents a generated image"""
    file_id: str
    prompt: str
    size: str
    model: str
    url: Optional[str] = None

    def get_download_url(self, base_url: str) -> str:
        """Get full download URL for the image"""
        return f"{base_url}/files/{self.file_id}/content"


class ImageClient:
    """
    Client for image generation and analysis
    """

    def __init__(self, base_client: Optional[BaseAPIClient] = None):
        """
        Initialize image client

        Args:
            base_client: Base API client (creates new if not provided)
        """
        self.client = base_client or BaseAPIClient()
        self.chat_client = ChatClient(base_client=self.client)
        self.generated_images: List[GeneratedImage] = []

    def generate_image(self,
                      prompt: str,
                      size: str = "512x512",
                      model: Optional[Union[Model, str]] = None,
                      save_path: Optional[Union[str, Path]] = None) -> GeneratedImage:
        """
        Generate an image from text prompt

        Args:
            prompt: Text prompt for image generation
            size: Image size (256x256, 512x512, 1024x1024)
            model: Model to use (defaults to GLM-4.5V-AWQ)
            save_path: Optional path to save the generated image

        Returns:
            GeneratedImage object with file details
        """
        # Validate size
        if size not in self.client.config.supported_image_sizes:
            raise InvalidRequestError(
                f"Invalid image size: {size}. "
                f"Supported sizes: {', '.join(self.client.config.supported_image_sizes)}"
            )

        # Determine model (vision model recommended)
        if model is None:
            model = Model.GLM_4_5V_AWQ
        if isinstance(model, Model):
            model = model.value

        logger.info(f"Generating image with prompt: {prompt[:50]}...")

        # Build request
        request_data = {
            "model": model,
            "prompt": prompt,
            "size": size
        }

        try:
            # Make request
            response = self.client.post(
                '/images/generations',
                json_data=request_data
            )

            # Parse response
            data = self.client.parse_response(response)

            # Extract file ID from response
            # Response format: [{"url": "/api/v1/files/{file_id}/content"}]
            if isinstance(data, list) and len(data) > 0:
                url = data[0].get('url', '')
                # Extract file ID from URL
                parts = url.split('/')
                if 'files' in parts:
                    file_id_index = parts.index('files') + 1
                    if file_id_index < len(parts):
                        file_id = parts[file_id_index]
                    else:
                        raise VTARCAPIException("Could not extract file ID from response")
                else:
                    raise VTARCAPIException("Invalid response format")
            else:
                raise VTARCAPIException("Empty or invalid response")

            # Create GeneratedImage object
            generated_image = GeneratedImage(
                file_id=file_id,
                prompt=prompt,
                size=size,
                model=model,
                url=url
            )

            # Store in history
            self.generated_images.append(generated_image)

            logger.info(f"Successfully generated image. File ID: {file_id}")

            # Download and save if requested
            if save_path:
                self.download_image(generated_image, save_path)

            return generated_image

        except Exception as e:
            raise VTARCAPIException(f"Failed to generate image: {e}")

    def download_image(self,
                      image: Union[GeneratedImage, str],
                      save_path: Union[str, Path]) -> Path:
        """
        Download generated image

        Args:
            image: GeneratedImage object or file_id
            save_path: Path to save the image

        Returns:
            Path to saved image
        """
        if isinstance(image, str):
            file_id = image
        else:
            file_id = image.file_id

        save_path = Path(save_path)

        # Create parent directory if needed
        save_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Downloading image {file_id} to {save_path}")

        try:
            # Get image content
            response = self.client.get(
                f'/files/{file_id}/content',
                stream=True
            )

            # Save to file
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            logger.info(f"Successfully saved image to {save_path}")
            return save_path

        except Exception as e:
            raise VTARCAPIException(f"Failed to download image: {e}")

    def get_image_bytes(self,
                       image: Union[GeneratedImage, str]) -> bytes:
        """
        Get generated image as bytes

        Args:
            image: GeneratedImage object or file_id

        Returns:
            Image data as bytes
        """
        if isinstance(image, str):
            file_id = image
        else:
            file_id = image.file_id

        try:
            response = self.client.get(f'/files/{file_id}/content')
            return response.content
        except Exception as e:
            raise VTARCAPIException(f"Failed to get image bytes: {e}")

    def analyze_image(self,
                     image_path: Union[str, Path],
                     prompt: str = "Describe this image",
                     model: Optional[Union[Model, str]] = None,
                     detailed: bool = False) -> str:
        """
        Analyze an image (image-to-text)

        Args:
            image_path: Path to image file
            prompt: Analysis prompt
            model: Model to use (defaults to GLM-4.5V-AWQ)
            detailed: Request detailed analysis

        Returns:
            Text description/analysis of the image
        """
        image_path = Path(image_path)

        # Validate file exists
        if not image_path.exists():
            raise InvalidRequestError(f"Image file not found: {image_path}")

        # Use vision model
        if model is None:
            model = Model.GLM_4_5V_AWQ
        if isinstance(model, Model):
            model = model.value

        # Convert image to base64
        image_base64 = self._encode_image(image_path)

        # Add detail request if needed
        if detailed:
            prompt = f"{prompt}. Please provide a detailed and comprehensive analysis."

        logger.info(f"Analyzing image: {image_path.name}")

        # Build multimodal message
        message_content = [
            {
                "type": "text",
                "text": prompt
            },
            {
                "type": "image_url",
                "image_url": {
                    "url": f"data:image/{image_path.suffix[1:]};base64,{image_base64}"
                }
            }
        ]

        # Create message
        messages = [ChatMessage("user", message_content)]

        # Get response
        response = self.chat_client.create_completion(
            messages=messages,
            model=model
        )

        # Extract content
        if isinstance(response, dict):
            choices = response.get('choices', [])
            if choices:
                return choices[0].get('message', {}).get('content', '')

        return ''

    def analyze_multiple_images(self,
                              image_paths: List[Union[str, Path]],
                              prompt: str,
                              model: Optional[Union[Model, str]] = None) -> str:
        """
        Analyze multiple images together

        Args:
            image_paths: List of image paths
            prompt: Analysis prompt
            model: Model to use

        Returns:
            Combined analysis
        """
        # Use vision model
        if model is None:
            model = Model.GLM_4_5V_AWQ
        if isinstance(model, Model):
            model = model.value

        # Build multimodal message
        message_content = [
            {
                "type": "text",
                "text": prompt
            }
        ]

        # Add all images
        for image_path in image_paths:
            image_path = Path(image_path)
            if not image_path.exists():
                logger.warning(f"Image not found: {image_path}")
                continue

            image_base64 = self._encode_image(image_path)
            message_content.append({
                "type": "image_url",
                "image_url": {
                    "url": f"data:image/{image_path.suffix[1:]};base64,{image_base64}"
                }
            })

        # Create message
        messages = [ChatMessage("user", message_content)]

        # Get response
        response = self.chat_client.create_completion(
            messages=messages,
            model=model
        )

        # Extract content
        if isinstance(response, dict):
            choices = response.get('choices', [])
            if choices:
                return choices[0].get('message', {}).get('content', '')

        return ''

    def compare_images(self,
                      image1_path: Union[str, Path],
                      image2_path: Union[str, Path],
                      comparison_aspects: Optional[List[str]] = None,
                      model: Optional[Union[Model, str]] = None) -> str:
        """
        Compare two images

        Args:
            image1_path: Path to first image
            image2_path: Path to second image
            comparison_aspects: Specific aspects to compare
            model: Model to use

        Returns:
            Comparison results
        """
        prompt = "Compare these two images"

        if comparison_aspects:
            prompt += " focusing on the following aspects:\n"
            for aspect in comparison_aspects:
                prompt += f"- {aspect}\n"
        else:
            prompt += " and describe the key similarities and differences."

        return self.analyze_multiple_images(
            [image1_path, image2_path],
            prompt,
            model
        )

    def extract_text_from_image(self,
                              image_path: Union[str, Path],
                              language: str = "English",
                              model: Optional[Union[Model, str]] = None) -> str:
        """
        Extract text (OCR) from image

        Args:
            image_path: Path to image
            language: Expected language of text
            model: Model to use

        Returns:
            Extracted text
        """
        prompt = f"Extract all text from this image. The text is in {language}. " \
                f"Provide only the extracted text without any additional commentary."

        return self.analyze_image(image_path, prompt, model)

    def generate_variations(self,
                          original_prompt: str,
                          num_variations: int = 3,
                          size: str = "512x512",
                          model: Optional[Union[Model, str]] = None,
                          save_directory: Optional[Union[str, Path]] = None) -> List[GeneratedImage]:
        """
        Generate multiple variations of an image

        Args:
            original_prompt: Base prompt
            num_variations: Number of variations to generate
            size: Image size
            model: Model to use
            save_directory: Directory to save images

        Returns:
            List of GeneratedImage objects
        """
        variations = []

        # Generate variation prompts
        variation_prompts = [
            original_prompt,  # Original
            f"{original_prompt}, artistic style",
            f"{original_prompt}, photorealistic",
            f"{original_prompt}, abstract interpretation",
            f"{original_prompt}, minimalist design",
            f"{original_prompt}, vibrant colors"
        ]

        # Use requested number of variations
        prompts_to_use = variation_prompts[:num_variations]

        for i, prompt in enumerate(prompts_to_use):
            try:
                save_path = None
                if save_directory:
                    save_dir = Path(save_directory)
                    save_dir.mkdir(parents=True, exist_ok=True)
                    save_path = save_dir / f"variation_{i+1}.png"

                image = self.generate_image(prompt, size, model, save_path)
                variations.append(image)

            except Exception as e:
                logger.error(f"Failed to generate variation {i+1}: {e}")

        return variations

    def _encode_image(self, image_path: Path) -> str:
        """
        Encode image to base64

        Args:
            image_path: Path to image

        Returns:
            Base64 encoded string
        """
        with open(image_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode("utf-8")

    def _decode_base64_image(self, base64_string: str) -> bytes:
        """
        Decode base64 image to bytes

        Args:
            base64_string: Base64 encoded image

        Returns:
            Image bytes
        """
        # Remove data URL prefix if present
        if ',' in base64_string:
            base64_string = base64_string.split(',')[1]

        return base64.b64decode(base64_string)

    def get_generation_history(self) -> List[GeneratedImage]:
        """Get list of generated images in this session"""
        return self.generated_images.copy()

    def clear_generation_history(self) -> None:
        """Clear generation history"""
        self.generated_images.clear()