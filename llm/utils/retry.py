"""
Retry logic and decorators for VT ARC API Client
"""

import time
import random
import functools
from typing import Any, Callable, Optional, Tuple, Type, Union
import logging

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from exceptions import (
    VTARCAPIException,
    RateLimitError,
    NetworkError,
    TimeoutError,
    APIKeyExhaustedError
)


logger = logging.getLogger(__name__)


def exponential_backoff(attempt: int, base_delay: float = 1.0,
                        max_delay: float = 60.0, jitter: bool = True) -> float:
    """
    Calculate exponential backoff delay

    Args:
        attempt: Current attempt number (0-based)
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds
        jitter: Add random jitter to prevent thundering herd

    Returns:
        Delay in seconds
    """
    delay = min(base_delay * (2 ** attempt), max_delay)

    if jitter:
        # Add random jitter between 0-25% of delay
        delay = delay * (1 + random.random() * 0.25)

    return delay


def should_retry(exception: Exception,
                 retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None) -> bool:
    """
    Determine if an exception should trigger a retry

    Args:
        exception: The exception that occurred
        retryable_exceptions: Tuple of exception types that should be retried

    Returns:
        True if should retry, False otherwise
    """
    if retryable_exceptions is None:
        retryable_exceptions = (
            RateLimitError,
            NetworkError,
            TimeoutError,
        )

    # Don't retry if all API keys exhausted
    if isinstance(exception, APIKeyExhaustedError):
        return False

    return isinstance(exception, retryable_exceptions)


def retry_with_backoff(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential: bool = True,
    jitter: bool = True,
    retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    on_retry: Optional[Callable[[Exception, int], None]] = None
) -> Callable:
    """
    Decorator for retrying functions with backoff

    Args:
        max_attempts: Maximum number of attempts
        base_delay: Base delay between retries in seconds
        max_delay: Maximum delay between retries
        exponential: Use exponential backoff
        jitter: Add random jitter to delays
        retryable_exceptions: Exceptions that trigger retry
        on_retry: Callback function called on each retry

    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)

                except Exception as e:
                    last_exception = e

                    # Check if we should retry
                    if not should_retry(e, retryable_exceptions):
                        logger.error(f"Non-retryable error in {func.__name__}: {e}")
                        raise

                    # Don't retry if this is the last attempt
                    if attempt >= max_attempts - 1:
                        logger.error(f"Max retries ({max_attempts}) exceeded for {func.__name__}")
                        raise

                    # Calculate delay
                    if exponential:
                        delay = exponential_backoff(attempt, base_delay, max_delay, jitter)
                    else:
                        delay = base_delay

                    # Special handling for rate limit errors
                    if isinstance(e, RateLimitError) and e.retry_after:
                        delay = max(delay, e.retry_after)

                    logger.warning(
                        f"Retry {attempt + 1}/{max_attempts} for {func.__name__} "
                        f"after {delay:.2f}s delay. Error: {e}"
                    )

                    # Call retry callback if provided
                    if on_retry:
                        on_retry(e, attempt)

                    # Wait before retry
                    time.sleep(delay)

            # Should not reach here, but raise last exception if we do
            if last_exception:
                raise last_exception

        return wrapper
    return decorator


class RetryPolicy:
    """
    Configurable retry policy for API operations
    """

    def __init__(self,
                 max_attempts: int = 3,
                 base_delay: float = 1.0,
                 max_delay: float = 60.0,
                 exponential: bool = True,
                 jitter: bool = True,
                 retryable_status_codes: Optional[Tuple[int, ...]] = None):
        """
        Initialize retry policy

        Args:
            max_attempts: Maximum number of attempts
            base_delay: Base delay between retries
            max_delay: Maximum delay between retries
            exponential: Use exponential backoff
            jitter: Add jitter to delays
            retryable_status_codes: HTTP status codes that should trigger retry
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential = exponential
        self.jitter = jitter
        self.retryable_status_codes = retryable_status_codes or (429, 500, 502, 503, 504)

    def should_retry_status(self, status_code: int) -> bool:
        """Check if HTTP status code should trigger retry"""
        return status_code in self.retryable_status_codes

    def get_delay(self, attempt: int) -> float:
        """Get delay for given attempt number"""
        if self.exponential:
            return exponential_backoff(attempt, self.base_delay, self.max_delay, self.jitter)
        return self.base_delay

    def execute_with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with retry policy

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result
        """
        last_exception = None

        for attempt in range(self.max_attempts):
            try:
                return func(*args, **kwargs)

            except Exception as e:
                last_exception = e

                if attempt >= self.max_attempts - 1:
                    raise

                delay = self.get_delay(attempt)
                logger.warning(f"Retrying after {delay:.2f}s. Error: {e}")
                time.sleep(delay)

        if last_exception:
            raise last_exception