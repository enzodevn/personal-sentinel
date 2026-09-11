"""Structured application logging without telemetry or credential payloads.

PURPOSE: Make collector failures diagnosable without exposing process arguments.
WHAT IT TEACHES: Log levels, JSON logs, rotation, and safe logging boundaries.
CAREER VALUE: Operational software and security tools require observable failures.
SYSTEM VALUE: Records application health while keeping normal CLI output readable.
CURRENT NECESSITY: HIGH; silent collector failure would make telemetry misleading.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path


class JsonFormatter(logging.Formatter):
    """Format a conservative set of log fields as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(verbose: bool = False) -> Path | None:
    """Configure rotating JSON logs and return the log path when available."""

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    log_directory = Path(os.environ.get("SENTINEL_LOG_DIR", "logs"))
    try:
        log_directory.mkdir(parents=True, exist_ok=True)
        log_path = log_directory / "sentinel.log"
        handler = RotatingFileHandler(
            log_path,
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
    except OSError:
        handler = logging.StreamHandler()
        log_path = None

    handler.setFormatter(JsonFormatter())
    root_logger.addHandler(handler)
    return log_path
