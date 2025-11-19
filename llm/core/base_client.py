"""
Base API client for VT ARC API
Handles authentication, key rotation, and core HTTP operations
"""

import json
import time
import requests
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
import logging

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import APIConfig, Model
from exceptions import (
    AuthenticationError,
    RateLimitError,
    APIKeyExhaustedError,
    NetworkError,
    TimeoutError,
    ResponseParsingError,
    VTARCAPIException
)
from utils.rate_limiter import APIKeyRotator
from utils.retry import retry_with_backoff, RetryPolicy
from utils.logger import APICallLogger, PerformanceLogger


logger = logging.getLogger(__name__)


class BaseAPIClient:
    """
    Base client for VT ARC API operations
    Handles authentication, key rotation, rate limiting, and retries
    """

    def __init__(self, config: Optional[APIConfig] = None):
        """
        Initialize base API client

        Args:
            config: API configuration (uses defaults if not provided)
        """
        self.config = config or APIConfig()
        self.key_rotator = APIKeyRotator(self.config.api_keys)
        self.retry_policy = RetryPolicy(
            max_attempts=self.config.max_retries,
            base_delay=self.config.retry_delay,
            exponential=self.config.exponential_backoff
        )

        # Initialize loggers
        self.api_logger = APICallLogger(logger)
        self.perf_logger = PerformanceLogger(logger)

        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'User-Agent': 'VT-ARC-API-Client/1.0'
        })

        logger.info(f"Initialized VT ARC API client with {len(self.config.api_keys)} API key(s)")

    def _get_auth_header(self, api_key: Optional[str] = None) -> Dict[str, str]:
        """
        Get authorization header with API key

        Args:
            api_key: Specific API key to use (uses rotation if not provided)

        Returns:
            Authorization header dict
        """
        if api_key:
            return {'Authorization': f'Bearer {api_key}'}

        # Get next available key from rotator
        key = self.key_rotator.get_next_key()
        if not key:
            if self.key_rotator.all_keys_exhausted():
                raise APIKeyExhaustedError("All API keys are exhausted")
            raise AuthenticationError("No available API key")

        return {'Authorization': f'Bearer {key}'}

    def _handle_response_error(self, response: requests.Response,
                              api_key: Optional[str] = None) -> None:
        """
        Handle HTTP error responses

        Args:
            response: HTTP response
            api_key: API key used for the request

        Raises:
            Appropriate exception based on response
        """
        status_code = response.status_code

        # Try to get error details from response
        try:
            error_data = response.json()
            error_message = error_data.get('error', {}).get('message', response.text)
        except:
            error_message = response.text

        if status_code == 401:
            if api_key:
                self.key_rotator.mark_exhausted(api_key)
            raise AuthenticationError(f"Authentication failed: {error_message}")

        elif status_code == 429:
            # Rate limit exceeded
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                retry_after = int(retry_after)
            if api_key:
                self.key_rotator.mark_exhausted(api_key, retry_after)
            raise RateLimitError(f"Rate limit exceeded: {error_message}", retry_after)

        elif status_code == 404:
            raise VTARCAPIException(f"Resource not found: {error_message}")

        elif status_code >= 500:
            raise NetworkError(f"Server error ({status_code}): {error_message}")

        else:
            raise VTARCAPIException(f"API error ({status_code}): {error_message}")

    @retry_with_backoff(max_attempts=3, retryable_exceptions=(NetworkError, TimeoutError, RateLimitError))
    def _make_request(self,
                     method: str,
                     endpoint: str,
                     headers: Optional[Dict[str, str]] = None,
                     json_data: Optional[Dict[str, Any]] = None,
                     data: Optional[Any] = None,
                     files: Optional[Dict[str, Any]] = None,
                     params: Optional[Dict[str, str]] = None,
                     timeout: Optional[int] = None,
                     stream: bool = False) -> requests.Response:
        """
        Make HTTP request with authentication and error handling

        Args:
            method: HTTP method
            endpoint: API endpoint (relative to base URL)
            headers: Additional headers
            json_data: JSON data for request body
            data: Form data for request body
            files: Files for multipart upload
            params: Query parameters
            timeout: Request timeout
            stream: Enable streaming response

        Returns:
            HTTP response

        Raises:
            Various exceptions based on response
        """
        # Get API key and wait if needed
        api_key = self.key_rotator.get_next_key()
        if not api_key:
            raise APIKeyExhaustedError("All API keys exhausted")

        wait_time = self.key_rotator.get_wait_time(api_key)
        if wait_time > 0:
            logger.info(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)

        # Build full URL
        url = f"{self.config.base_url}/{endpoint.lstrip('/')}"

        # Build headers
        request_headers = self._get_auth_header(api_key)
        if headers:
            request_headers.update(headers)

        # Set timeout
        if timeout is None:
            timeout = self.config.request_timeout

        # Log request
        req_id = self.api_logger.log_request(method, url, request_headers, json_data)

        # Start performance tracking
        start_time = time.time()

        try:
            # Make request
            response = self.session.request(
                method=method,
                url=url,
                headers=request_headers,
                json=json_data,
                data=data,
                files=files,
                params=params,
                timeout=timeout,
                stream=stream
            )

            # Record successful request
            self.key_rotator.record_request(api_key)

            # Track performance
            duration = time.time() - start_time
            self.perf_logger.log_timing(f"{method} {endpoint}", duration)

            # Check for errors
            if not response.ok:
                self._handle_response_error(response, api_key)

            # Log successful response
            if not stream:
                try:
                    response_data = response.json() if response.text else {}
                    self.api_logger.log_response(req_id, response.status_code, response_data)
                except:
                    self.api_logger.log_response(req_id, response.status_code)

            return response

        except requests.exceptions.Timeout:
            duration = time.time() - start_time
            self.api_logger.log_response(req_id, 0, error=f"Timeout after {duration:.2f}s")
            raise TimeoutError(f"Request timed out after {timeout}s")

        except requests.exceptions.ConnectionError as e:
            self.api_logger.log_response(req_id, 0, error=str(e))
            raise NetworkError(f"Connection error: {e}")

        except requests.exceptions.RequestException as e:
            self.api_logger.log_response(req_id, 0, error=str(e))
            raise NetworkError(f"Request error: {e}")

    def get(self, endpoint: str, **kwargs) -> requests.Response:
        """Make GET request"""
        return self._make_request('GET', endpoint, **kwargs)

    def post(self, endpoint: str, **kwargs) -> requests.Response:
        """Make POST request"""
        return self._make_request('POST', endpoint, **kwargs)

    def put(self, endpoint: str, **kwargs) -> requests.Response:
        """Make PUT request"""
        return self._make_request('PUT', endpoint, **kwargs)

    def delete(self, endpoint: str, **kwargs) -> requests.Response:
        """Make DELETE request"""
        return self._make_request('DELETE', endpoint, **kwargs)

    def parse_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        Parse JSON response

        Args:
            response: HTTP response

        Returns:
            Parsed JSON data

        Raises:
            ResponseParsingError if parsing fails
        """
        try:
            return response.json()
        except json.JSONDecodeError as e:
            raise ResponseParsingError(f"Failed to parse response: {e}")

    def test_connection(self) -> bool:
        """
        Test API connection and authentication

        Returns:
            True if connection successful
        """
        try:
            # Try to get models list as a simple test
            response = self.get('/models')
            return response.ok
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

    def get_remaining_requests(self) -> Dict[str, Dict[str, int]]:
        """
        Get remaining requests for all API keys

        Returns:
            Dict mapping API keys to remaining request counts
        """
        result = {}
        for key in self.config.api_keys:
            masked_key = f"{key[:7]}...{key[-4:]}" if len(key) > 11 else "***"
            if key in self.key_rotator.rate_limiters:
                result[masked_key] = self.key_rotator.rate_limiters[key].get_remaining_requests()
        return result

    def reset_rate_limits(self, api_key: Optional[str] = None) -> None:
        """
        Reset rate limits

        Args:
            api_key: Specific key to reset (all if not provided)
        """
        if api_key:
            self.key_rotator.reset_key(api_key)
        else:
            self.key_rotator.reset_all()

    def close(self) -> None:
        """Close the client session"""
        self.session.close()
        self.perf_logger.log_summary()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()