"""Centralized logging setup using Rich for readable console output."""

from __future__ import annotations

import logging

from rich.logging import RichHandler

_CONFIGURED = False


def setup_logging(level: str = "INFO") -> logging.Logger:
    global _CONFIGURED
    logger = logging.getLogger("boss_auditor")

    if not _CONFIGURED:
        handler = RichHandler(
            show_time=True, show_path=False, markup=True, rich_tracebacks=True
        )
        handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
        logger.addHandler(handler)
        logger.propagate = False
        _CONFIGURED = True

    logger.setLevel(level.upper())
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger("boss_auditor")
