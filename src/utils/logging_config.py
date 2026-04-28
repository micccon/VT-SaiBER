"""
Logging configuration helpers.
"""

from __future__ import annotations

import logging
import os


def setup_logging(default_level: str = "INFO") -> None:
    """Configure process-wide logging once from LOG_LEVEL or the provided default."""

    level_name = os.getenv("LOG_LEVEL", default_level).upper()
    level = getattr(logging, level_name, logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
