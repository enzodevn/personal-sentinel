"""Process lifecycle monitoring based on consecutive read-only snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sentinel.collectors.processes import ProcessCollector
from sentinel.models import (
    CollectionError,
    CollectionResult,
    ProcessInfo,
    SecurityEvent,
)
from sentinel.storage import EventStore
from sentinel.windows_events import WindowsEventLogCollector


ProcessIdentity = tuple[int, str]


class ProcessDeltaMonitor:
    """Emit lifecycle events only when process identity can be correlated."""

    def __init__(self, collector: ProcessCollector | None = None) -> None:
        self.collector = collector or ProcessCollector()
        self._previous: dict[ProcessIdentity, ProcessInfo] | None = None
        self._previous_inaccessible: set[int] = set()
        self._pending_state: tuple[
            dict[ProcessIdentity, ProcessInfo],
            set[int],
        ] | None = None

    def collect(self) -> CollectionResult[list[SecurityEvent]]:
        self._pending_state = None
        result = self.collector.collect()
        if any(error.scope == "process.enumeration" for error in result.errors):
            return CollectionResult(data=[], errors=result.errors)

        current = {
            identity: process
            for process in result.data
            if (identity := self._identity(process)) is not None
        }
        inaccessible = {
            int(error.scope.removeprefix("process.pid."))
            for error in result.errors
            if error.scope.startswith("process.pid.")
            and error.scope.removeprefix("process.pid.").isdigit()
        }

        if self._previous is None:
            self._pending_state = (current, inaccessible)
            return CollectionResult(data=[], errors=result.errors)

        observed_at = datetime.now(UTC)
        events: list[SecurityEvent] = []
        for identity, process in current.items():
            if identity in self._previous or identity[0] in self._previous_inaccessible:
                continue
            events.append(self._event("started", process, observed_at))

        for identity, process in self._previous.items():
            if identity in current or identity[0] in inaccessible:
                continue
            events.append(self._event("exited", process, observed_at))

        next_previous = {
            **{
                identity: process
                for identity, process in self._previous.items()
                if process.pid in inaccessible
            },
            **current,
        }
        self._pending_state = (next_previous, inaccessible)
        return CollectionResult(data=events, errors=result.errors)

    def commit(self) -> None:
        """Accept the latest snapshot after its events have been persisted."""

        if self._pending_state is not None:
            self._previous, self._previous_inaccessible = self._pending_state
            self._pending_state = None

    @staticmethod
    def _identity(process: ProcessInfo) -> ProcessIdentity | None:
        if process.started_at is None:
            return None
        return process.pid, process.started_at.astimezone(UTC).isoformat()

    @staticmethod
    def _event(
        action: str,
        process: ProcessInfo,
        observed_at: datetime,
    ) -> SecurityEvent:
        started_at = process.started_at
        if started_at is None:
            raise ValueError("process identity requires a start time")
        identity = started_at.astimezone(UTC).isoformat()
        return SecurityEvent(
            event_id=f"process:{action}:{process.pid}:{identity}",
            source="process.snapshot",
            event_type=f"process.{action}",
            timestamp=started_at if action == "started" else observed_at,
            process_id=process.pid,
            details={
                "name": process.name,
                "path": process.path,
                "parent_pid": process.parent_pid,
                "parent_name": process.parent_name,
            },
        )


@dataclass(frozen=True, slots=True)
class MonitorCycle:
    observed_events: int
    stored_events: int
    pruned_events: int
    errors: tuple[CollectionError, ...]


class SentinelMonitor:
    """Run one read-only collection cycle and persist its normalized events."""

    def __init__(
        self,
        store: EventStore,
        *,
        process_monitor: ProcessDeltaMonitor | None = None,
        event_log_collector: WindowsEventLogCollector | None = None,
    ) -> None:
        self.store = store
        self.process_monitor = process_monitor or ProcessDeltaMonitor()
        self.event_log_collector = event_log_collector or WindowsEventLogCollector()

    def collect_once(self) -> MonitorCycle:
        process_result = self.process_monitor.collect()
        event_log_result = self.event_log_collector.collect(self.store)
        events = process_result.data + list(event_log_result.events)
        stored = self.store.persist_batch(events, event_log_result.checkpoints)
        self.process_monitor.commit()
        pruned = self.store.prune()
        return MonitorCycle(
            observed_events=len(events),
            stored_events=stored,
            pruned_events=pruned,
            errors=process_result.errors + event_log_result.errors,
        )
