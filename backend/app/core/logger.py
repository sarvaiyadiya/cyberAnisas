"""
core/logger.py

Centralised logging configuration for ANISAS.

Usage:
    from app.core.logger import get_logger
    logger = get_logger(__name__)
"""

import logging
import sys

# ── Root formatter ────────────────────────────────────────────────────────────
_formatter = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ── Console handler ───────────────────────────────────────────────────────────
_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(_formatter)


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger with the ANISAS formatter attached.

    Args:
        name: Typically ``__name__`` of the calling module.

    Returns:
        A configured :class:`logging.Logger` instance.
    """
    log = logging.getLogger(name)

    if not log.handlers:
        log.addHandler(_console_handler)

    log.setLevel(logging.INFO)
    log.propagate = False

    return log


# ── Backwards-compatible module-level logger ──────────────────────────────────
# Existing code that does `from app.core.logger import logger` keeps working.
logger = get_logger("ANISAS")