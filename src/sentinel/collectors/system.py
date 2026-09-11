"""Collect a small system-health snapshot.

PURPOSE: Answer whether the observed host and Sentinel's basic inputs are healthy.
WHAT IT TEACHES: OS identity, CPU, memory, disks, and defensive error boundaries.
CAREER VALUE: These signals are foundational in observability and endpoint agents.
SYSTEM VALUE: Supplies the `sentinel status` health summary.
CURRENT NECESSITY: HIGH; it is the smallest useful end-to-end collector.
"""

from __future__ import annotations

import os
import platform
import socket
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import psutil

from sentinel.models import CollectionError, CollectionResult, SystemSnapshot


Metric = TypeVar("Metric")


class SystemCollector:
    """Read system metrics without modifying operating-system state."""

    def __init__(self, cpu_sample_seconds: float = 0.1) -> None:
        if cpu_sample_seconds < 0:
            raise ValueError("cpu_sample_seconds must be non-negative")
        self.cpu_sample_seconds = cpu_sample_seconds

    def collect(self) -> CollectionResult[SystemSnapshot]:
        errors: list[CollectionError] = []

        cpu = self._read(
            "system.cpu",
            lambda: float(psutil.cpu_percent(interval=self.cpu_sample_seconds)),
            errors,
        )
        memory = self._read(
            "system.memory",
            lambda: float(psutil.virtual_memory().percent),
            errors,
        )
        disk = self._read(
            "system.disk",
            lambda: float(psutil.disk_usage(str(self._system_root())).percent),
            errors,
        )
        process_count = self._read(
            "system.processes",
            lambda: len(psutil.pids()),
            errors,
        )

        snapshot = SystemSnapshot(
            hostname=socket.gethostname(),
            operating_system=platform.system() or "Unknown",
            os_version=platform.version() or "Unknown",
            cpu_percent=cpu,
            memory_percent=memory,
            disk_percent=disk,
            process_count=process_count,
        )
        return CollectionResult(data=snapshot, errors=tuple(errors))

    @staticmethod
    def _system_root() -> Path:
        if os.name == "nt":
            return Path(f"{os.environ.get('SystemDrive', 'C:')}\\")
        return Path("/")

    @staticmethod
    def _read(
        scope: str,
        operation: Callable[[], Metric],
        errors: list[CollectionError],
    ) -> Metric | None:
        try:
            return operation()
        except Exception as error:  # Collector boundary: preserve other metrics.
            errors.append(CollectionError.from_exception(scope, error))
            return None
