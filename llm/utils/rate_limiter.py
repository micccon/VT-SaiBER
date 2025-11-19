"""
Rate limiting utilities for VT ARC API Client
"""

import time
import threading
from collections import deque
from typing import Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class RateLimitWindow:
    """Tracks requests within a time window"""
    window_size: int  # Window size in seconds
    max_requests: int  # Maximum requests allowed in window
    requests: deque = field(default_factory=deque)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def can_make_request(self) -> bool:
        """Check if a request can be made within rate limits"""
        with self.lock:
            now = time.time()
            # Remove expired requests
            while self.requests and self.requests[0] < now - self.window_size:
                self.requests.popleft()

            return len(self.requests) < self.max_requests

    def add_request(self) -> None:
        """Record a new request"""
        with self.lock:
            now = time.time()
            # Clean old requests
            while self.requests and self.requests[0] < now - self.window_size:
                self.requests.popleft()

            self.requests.append(now)

    def time_until_next_request(self) -> float:
        """Calculate time to wait until next request can be made"""
        with self.lock:
            now = time.time()
            # Clean old requests
            while self.requests and self.requests[0] < now - self.window_size:
                self.requests.popleft()

            if len(self.requests) < self.max_requests:
                return 0.0

            # Calculate when the oldest request will expire
            oldest_request = self.requests[0]
            time_to_wait = (oldest_request + self.window_size) - now
            return max(0.0, time_to_wait)

    def reset(self) -> None:
        """Reset the rate limit window"""
        with self.lock:
            self.requests.clear()


class RateLimiter:
    """
    Rate limiter for API requests with multiple window sizes
    Implements the VT ARC API limits:
    - 60 requests per minute
    - 1000 requests per hour
    - 2000 requests per 3-hour sliding window
    """

    def __init__(self,
                 requests_per_minute: int = 60,
                 requests_per_hour: int = 1000,
                 requests_per_3_hours: int = 2000):
        """Initialize rate limiter with specified limits"""
        self.windows = {
            'minute': RateLimitWindow(60, requests_per_minute),
            'hour': RateLimitWindow(3600, requests_per_hour),
            'three_hours': RateLimitWindow(10800, requests_per_3_hours)
        }
        self.enabled = True
        self.lock = threading.Lock()

    def can_make_request(self) -> bool:
        """Check if request can be made within all rate limits"""
        if not self.enabled:
            return True

        for window in self.windows.values():
            if not window.can_make_request():
                return False
        return True

    def wait_if_needed(self) -> float:
        """Wait if necessary to comply with rate limits, returns wait time"""
        if not self.enabled:
            return 0.0

        max_wait = 0.0
        for window in self.windows.values():
            wait_time = window.time_until_next_request()
            max_wait = max(max_wait, wait_time)

        if max_wait > 0:
            time.sleep(max_wait)

        return max_wait

    def record_request(self) -> None:
        """Record that a request was made"""
        if not self.enabled:
            return

        for window in self.windows.values():
            window.add_request()

    def get_remaining_requests(self) -> Dict[str, int]:
        """Get remaining requests for each window"""
        remaining = {}
        for name, window in self.windows.items():
            with window.lock:
                now = time.time()
                # Clean old requests
                while window.requests and window.requests[0] < now - window.window_size:
                    window.requests.popleft()

                remaining[name] = window.max_requests - len(window.requests)

        return remaining

    def reset(self) -> None:
        """Reset all rate limit windows"""
        for window in self.windows.values():
            window.reset()

    def disable(self) -> None:
        """Disable rate limiting"""
        self.enabled = False

    def enable(self) -> None:
        """Enable rate limiting"""
        self.enabled = True


class APIKeyRotator:
    """Manages rotation between multiple API keys to distribute load"""

    def __init__(self, api_keys: list):
        """Initialize with list of API keys"""
        if not api_keys:
            raise ValueError("At least one API key is required")

        self.api_keys = api_keys
        self.current_index = 0
        self.rate_limiters = {
            key: RateLimiter() for key in api_keys
        }
        self.lock = threading.Lock()
        self.exhausted_keys = set()
        self.exhausted_until = {}  # key -> timestamp when available again

    def get_next_key(self) -> Optional[str]:
        """Get next available API key"""
        with self.lock:
            # Clean up exhausted keys that might be available now
            now = time.time()
            keys_to_unexhaust = []
            for key, until_time in self.exhausted_until.items():
                if now >= until_time:
                    keys_to_unexhaust.append(key)

            for key in keys_to_unexhaust:
                self.exhausted_keys.discard(key)
                del self.exhausted_until[key]

            # Find next available key
            attempts = 0
            while attempts < len(self.api_keys):
                key = self.api_keys[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.api_keys)

                if key not in self.exhausted_keys:
                    limiter = self.rate_limiters[key]
                    if limiter.can_make_request():
                        return key

                attempts += 1

            # No immediately available key, find the one available soonest
            min_wait = float('inf')
            best_key = None

            for key in self.api_keys:
                if key not in self.exhausted_keys:
                    limiter = self.rate_limiters[key]
                    wait_time = limiter.windows['minute'].time_until_next_request()
                    if wait_time < min_wait:
                        min_wait = wait_time
                        best_key = key

            return best_key

    def record_request(self, api_key: str) -> None:
        """Record that a request was made with this key"""
        if api_key in self.rate_limiters:
            self.rate_limiters[api_key].record_request()

    def mark_exhausted(self, api_key: str, retry_after: Optional[int] = None) -> None:
        """Mark an API key as exhausted"""
        with self.lock:
            self.exhausted_keys.add(api_key)
            if retry_after:
                self.exhausted_until[api_key] = time.time() + retry_after
            else:
                # Default to 1 hour
                self.exhausted_until[api_key] = time.time() + 3600

    def get_wait_time(self, api_key: str) -> float:
        """Get wait time for specific API key"""
        if api_key in self.rate_limiters:
            return self.rate_limiters[api_key].wait_if_needed()
        return 0.0

    def all_keys_exhausted(self) -> bool:
        """Check if all API keys are exhausted"""
        with self.lock:
            return len(self.exhausted_keys) >= len(self.api_keys)

    def reset_key(self, api_key: str) -> None:
        """Reset rate limiter for specific key"""
        with self.lock:
            if api_key in self.rate_limiters:
                self.rate_limiters[api_key].reset()
            self.exhausted_keys.discard(api_key)
            self.exhausted_until.pop(api_key, None)

    def reset_all(self) -> None:
        """Reset all rate limiters and exhaustion status"""
        with self.lock:
            for limiter in self.rate_limiters.values():
                limiter.reset()
            self.exhausted_keys.clear()
            self.exhausted_until.clear()
            self.current_index = 0