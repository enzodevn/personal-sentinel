"""Predictable, typed contracts shared by Sentinel collectors.

PURPOSE: Keep operating-system data separate from presentation code.
WHAT IT TEACHES: Dataclasses, typing, immutability, and data contracts.
CAREER VALUE: The same boundary is used by backend and telemetry systems.
SYSTEM VALUE: Every collector returns a consistent result with explicit errors.
CURRENT NECESSITY: HIGH; collectors need a stable contract before storage exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Generic, Mapping, TypeVar


T = TypeVar("T")


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class CollectionError:
    """A non-fatal problem encountered while collecting telemetry."""

    scope: str
    error_type: str
    message: str

    @classmethod
    def from_exception(cls, scope: str, error: Exception) -> CollectionError:
        return cls(
            scope=scope,
            error_type=type(error).__name__,
            message=str(error) or "No error detail was provided.",
        )


@dataclass(frozen=True, slots=True)
class CollectionResult(Generic[T]):
    """Data plus any errors that did not justify crashing the application."""

    data: T
    collected_at: datetime = field(default_factory=utc_now)
    errors: tuple[CollectionError, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass(frozen=True, slots=True)
class SystemSnapshot:
    hostname: str
    operating_system: str
    os_version: str
    cpu_percent: float | None
    memory_percent: float | None
    disk_percent: float | None
    process_count: int | None


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    pid: int
    parent_pid: int | None
    name: str
    path: str | None
    username: str | None
    started_at: datetime | None
    cpu_percent: float | None
    memory_mb: float | None
    command_line: tuple[str, ...]
    parent_name: str | None = None


@dataclass(frozen=True, slots=True)
class NetworkConnection:
    protocol: str
    local_address: str | None
    local_port: int | None
    remote_address: str | None
    remote_port: int | None
    status: str
    pid: int | None
    process_name: str | None


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """A normalized, locally stored telemetry event; not a threat verdict."""

    event_id: str
    source: str
    event_type: str
    timestamp: datetime
    process_id: int | None
    details: Mapping[str, str | int | float | bool | None]

    def __post_init__(self) -> None:
        if not self.timestamp.tzinfo or self.timestamp.utcoffset() is None:
            raise ValueError("event timestamps must be timezone-aware")
