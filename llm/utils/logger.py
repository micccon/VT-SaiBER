"""
Logging utilities for VT ARC API Client
"""

import logging
import sys
from typing import Optional
from pathlib import Path
from datetime import datetime


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for console output"""

    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'

    def format(self, record):
        # Add color to log level if outputting to terminal
        if sys.stderr.isatty():
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"

        # Format the message
        message = super().format(record)

        # Reset color at the end
        if sys.stderr.isatty():
            record.levelname = levelname  # Reset for next use

        return message


def setup_logger(
    name: str = "vt_arc_api",
    level: str = "INFO",
    log_file: Optional[str] = None,
    enable_console: bool = True,
    enable_color: bool = True
) -> logging.Logger:
    """
    Set up logger with file and console handlers

    Args:
        name: Logger name
        level: Logging level
        log_file: Path to log file (optional)
        enable_console: Enable console output
        enable_color: Enable colored console output

    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)

    # Clear any existing handlers
    logger.handlers.clear()

    # Set level
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)

    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )

    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(log_level)

        if enable_color and sys.stderr.isatty():
            colored_formatter = ColoredFormatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%H:%M:%S'
            )
            console_handler.setFormatter(colored_formatter)
        else:
            console_handler.setFormatter(simple_formatter)

        logger.addHandler(console_handler)

    # File handler
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_path, encoding='utf-8')
            file_handler.setLevel(log_level)
            file_handler.setFormatter(detailed_formatter)
            logger.addHandler(file_handler)

        except Exception as e:
            logger.error(f"Failed to create log file handler: {e}")

    return logger


class APICallLogger:
    """Logger specifically for API calls with request/response tracking"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize API call logger"""
        self.logger = logger or logging.getLogger(__name__)
        self.request_id = 0

    def log_request(self, method: str, url: str, headers: dict,
                   data: Optional[dict] = None) -> int:
        """
        Log API request

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            data: Request data

        Returns:
            Request ID for tracking
        """
        self.request_id += 1
        req_id = self.request_id

        # Mask authorization header
        safe_headers = headers.copy()
        if 'Authorization' in safe_headers:
            auth_value = safe_headers['Authorization']
            if auth_value.startswith('Bearer '):
                key = auth_value[7:]
                masked_key = f"{key[:7]}...{key[-4:]}" if len(key) > 11 else "***"
                safe_headers['Authorization'] = f"Bearer {masked_key}"

        self.logger.debug(
            f"[REQ-{req_id}] {method} {url}\n"
            f"Headers: {safe_headers}\n"
            f"Data: {data}"
        )

        return req_id

    def log_response(self, req_id: int, status_code: int,
                    response_data: Optional[dict] = None,
                    error: Optional[str] = None):
        """
        Log API response

        Args:
            req_id: Request ID from log_request
            status_code: HTTP status code
            response_data: Response data
            error: Error message if failed
        """
        if error:
            self.logger.error(f"[RES-{req_id}] Status: {status_code}, Error: {error}")
        else:
            self.logger.debug(
                f"[RES-{req_id}] Status: {status_code}\n"
                f"Response: {response_data}"
            )

    def log_retry(self, req_id: int, attempt: int, reason: str):
        """Log retry attempt"""
        self.logger.warning(
            f"[RETRY-{req_id}] Attempt {attempt}, Reason: {reason}"
        )


class PerformanceLogger:
    """Logger for tracking performance metrics"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize performance logger"""
        self.logger = logger or logging.getLogger(__name__)
        self.metrics = {}

    def log_timing(self, operation: str, duration: float):
        """Log operation timing"""
        self.logger.info(f"[PERF] {operation} completed in {duration:.3f}s")

        # Track metrics
        if operation not in self.metrics:
            self.metrics[operation] = {
                'count': 0,
                'total_time': 0,
                'min_time': float('inf'),
                'max_time': 0
            }

        metric = self.metrics[operation]
        metric['count'] += 1
        metric['total_time'] += duration
        metric['min_time'] = min(metric['min_time'], duration)
        metric['max_time'] = max(metric['max_time'], duration)

    def get_summary(self) -> dict:
        """Get performance summary"""
        summary = {}
        for operation, metric in self.metrics.items():
            if metric['count'] > 0:
                summary[operation] = {
                    'count': metric['count'],
                    'avg_time': metric['total_time'] / metric['count'],
                    'min_time': metric['min_time'],
                    'max_time': metric['max_time'],
                    'total_time': metric['total_time']
                }
        return summary

    def log_summary(self):
        """Log performance summary"""
        summary = self.get_summary()
        if summary:
            self.logger.info("[PERF] Performance Summary:")
            for operation, stats in summary.items():
                self.logger.info(
                    f"  {operation}: "
                    f"count={stats['count']}, "
                    f"avg={stats['avg_time']:.3f}s, "
                    f"min={stats['min_time']:.3f}s, "
                    f"max={stats['max_time']:.3f}s"
                )