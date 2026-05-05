from __future__ import annotations

import sys
from pathlib import Path
from loguru import logger as _logger

from spoof.models import LogConfig


def setup_logger(config: LogConfig) -> None:
    _logger.remove()

    _logger.add(
        sys.stderr,
        format="<level>{time:HH:mm:ss.SSS} | {level:<8}</level> | <cyan>{module}</cyan>:<cyan>{function}</cyan> | <level>{message}</level>",
        level=config.level,
        colorize=True,
    )

    if config.file:
        log_path = Path(config.file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        _logger.add(
            str(log_path),
            format=config.format,
            level=config.level,
            rotation=config.rotation,
            retention=config.retention,
            encoding="utf-8",
        )

    _logger.debug("Logger initialized")


def get_logger():
    return _logger
