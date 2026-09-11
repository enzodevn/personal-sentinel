"""Collect process snapshots with a short CPU sampling window.

PURPOSE: Show which programs are executing and their parent/resource context.
WHAT IT TEACHES: PID/PPID, process trees, memory, CPU sampling, and permissions.
CAREER VALUE: Process telemetry is central to EDR, SOC, and host observability.
SYSTEM VALUE: Establishes the raw data later baselines and rules will consume.
CURRENT NECESSITY: HIGH; process observation is a V0.1 foundation.
"""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import UTC, datetime

import psutil

from sentinel.models import CollectionError, CollectionResult, ProcessInfo


PROCESS_ATTRIBUTES = (
    "pid",
    "ppid",
    "name",
    "exe",
    "username",
    "create_time",
    "memory_info",
    "cmdline",
)


class ProcessCollector:
    """Read current processes; inaccessible or exited processes become warnings."""

    def __init__(self, cpu_sample_seconds: float = 0.1) -> None:
        if cpu_sample_seconds < 0:
            raise ValueError("cpu_sample_seconds must be non-negative")
        self.cpu_sample_seconds = cpu_sample_seconds

    def collect(self) -> CollectionResult[list[ProcessInfo]]:
        errors: list[CollectionError] = []
        try:
            processes = list(
                psutil.process_iter(attrs=PROCESS_ATTRIBUTES, ad_value=None)
            )
        except Exception as error:  # Failure to enumerate is collector-wide.
            errors.append(CollectionError.from_exception("process.enumeration", error))
            return CollectionResult(data=[], errors=tuple(errors))

        sampled: list[psutil.Process] = []
        for process in processes:
            try:
                process.cpu_percent(interval=None)
                sampled.append(process)
            except Exception as error:  # Per-process failures must not stop the snapshot.
                errors.append(self._process_error(process, error))

        if sampled and self.cpu_sample_seconds:
            time.sleep(self.cpu_sample_seconds)

        snapshots: list[ProcessInfo] = []
        for process in sampled:
            try:
                snapshots.append(self._snapshot(process))
            except Exception as error:  # Per-process failures must not stop the snapshot.
                errors.append(self._process_error(process, error))

        names_by_pid = {process.pid: process.name for process in snapshots}
        with_parents = [
            replace(
                process,
                parent_name=names_by_pid.get(process.parent_pid),
            )
            for process in snapshots
        ]
        with_parents.sort(key=lambda process: process.pid)
        return CollectionResult(data=with_parents, errors=tuple(errors))

    @staticmethod
    def _snapshot(process: psutil.Process) -> ProcessInfo:
        info = process.info
        started_at = None
        if info.get("create_time") is not None:
            started_at = datetime.fromtimestamp(float(info["create_time"]), UTC)

        memory = info.get("memory_info")
        memory_mb = None if memory is None else round(memory.rss / (1024 * 1024), 2)
        command_line = tuple(str(part) for part in (info.get("cmdline") or ()))

        return ProcessInfo(
            pid=int(info["pid"]),
            parent_pid=(
                int(info["ppid"]) if info.get("ppid") is not None else None
            ),
            name=str(info.get("name") or "<unknown>"),
            path=str(info["exe"]) if info.get("exe") else None,
            username=str(info["username"]) if info.get("username") else None,
            started_at=started_at,
            cpu_percent=float(process.cpu_percent(interval=None)),
            memory_mb=memory_mb,
            command_line=command_line,
        )

    @staticmethod
    def _process_error(
        process: psutil.Process,
        error: Exception,
    ) -> CollectionError:
        pid = getattr(process, "pid", "unknown")
        return CollectionError.from_exception(f"process.pid.{pid}", error)
