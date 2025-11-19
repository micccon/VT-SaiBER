"""
Custom exception classes for VT ARC API Client
"""

from typing import Optional, Dict, Any


class VTARCAPIException(Exception):
    """Base exception class for all VT ARC API exceptions"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class AuthenticationError(VTARCAPIException):
    """Raised when authentication fails"""
    pass


class RateLimitError(VTARCAPIException):
    """Raised when rate limit is exceeded"""

    def __init__(self, message: str, retry_after: Optional[int] = None, **kwargs):
        super().__init__(message, kwargs)
        self.retry_after = retry_after


class APIKeyExhaustedError(VTARCAPIException):
    """Raised when all API keys are exhausted"""
    pass


class FileUploadError(VTARCAPIException):
    """Raised when file upload fails"""
    pass


class ModelNotAvailableError(VTARCAPIException):
    """Raised when requested model is not available"""
    pass


class InvalidRequestError(VTARCAPIException):
    """Raised when request parameters are invalid"""
    pass


class NetworkError(VTARCAPIException):
    """Raised when network-related errors occur"""
    pass


class TimeoutError(VTARCAPIException):
    """Raised when request times out"""
    pass


class ResponseParsingError(VTARCAPIException):
    """Raised when response cannot be parsed"""
    pass