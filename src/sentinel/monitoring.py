"""Process lifecycle monitoring based on consecutive read-only snapshots."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

from sentinel.collectors.network import NetworkCollector
from sentinel.collectors.processes import ProcessCollector
from sentinel.models import (
    CollectionError,
    CollectionResult,
    NetworkConnection,
    ProcessInfo,
    SecurityEvent,
)
from sentinel.storage import EventStore
from sentinel.windows_events import WindowsEventLogCollector


ProcessIdentity = tuple[int, str]
NetworkIdentity = tuple[
    str,
    str | None,
    int | None,
    str | None,
    int | None,
    int | None,
]
_TCP_CLOSING_STATES = frozenset(
    {
        "CLOSE",
        "CLOSE_WAIT",
        "CLOSING",
        "DELETE_TCB",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "LAST_ACK",
        "TIME_WAIT",
    }
)


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


class NetworkDeltaMonitor:
    """Emit endpoint lifecycle events from read-only connection snapshots."""

    def __init__(self, collector: NetworkCollector | None = None) -> None:
        self.collector = collector or NetworkCollector()
        self._previous: dict[NetworkIdentity, NetworkConnection] | None = None
        self._pending_state: dict[NetworkIdentity, NetworkConnection] | None = None

    def collect(self) -> CollectionResult[list[SecurityEvent]]:
        self._pending_state = None
        result = self.collector.collect()
        if any(error.scope == "network.enumeration" for error in result.errors):
            return CollectionResult(data=[], errors=result.errors)

        previous = self._previous or {}
        current: dict[NetworkIdentity, NetworkConnection] = {}
        for connection in result.data:
            identity = self._identity(connection)
            if identity is None:
                continue
            existing = current.get(identity, previous.get(identity))
            if (
                connection.protocol == "TCP"
                and existing is not None
                and existing.pid not in (None, 0)
                and connection.pid in (None, 0)
            ):
                current[identity] = existing
            else:
                current[identity] = connection
        incomplete = any(
            error.scope.startswith("network.connection.")
            for error in result.errors
        )
        if self._previous is None:
            self._pending_state = current
            return CollectionResult(data=[], errors=result.errors)

        observed_at = datetime.now(UTC)
        events = [
            self._event("opened", connection, identity, observed_at)
            for identity, connection in current.items()
            if identity not in self._previous
        ]
        events.extend(
            self._event("closed", connection, identity, observed_at)
            for identity, connection in self._previous.items()
            if identity not in current and not incomplete
        )

        if incomplete:
            current.update(
                {
                    identity: connection
                    for identity, connection in self._previous.items()
                    if identity not in current
                }
            )
        self._pending_state = current
        return CollectionResult(data=events, errors=result.errors)

    def commit(self) -> None:
        """Accept the latest snapshot after its events have been persisted."""

        if self._pending_state is not None:
            self._previous = self._pending_state
            self._pending_state = None

    @staticmethod
    def _identity(connection: NetworkConnection) -> NetworkIdentity | None:
        if (
            connection.protocol == "TCP"
            and connection.status.upper() in _TCP_CLOSING_STATES
        ):
            return None
        return (
            connection.protocol,
            connection.local_address,
            connection.local_port,
            connection.remote_address,
            connection.remote_port,
            connection.pid if connection.protocol == "UDP" else None,
        )

    @staticmethod
    def _event(
        action: str,
        connection: NetworkConnection,
        identity: NetworkIdentity,
        observed_at: datetime,
    ) -> SecurityEvent:
        fingerprint = hashlib.sha256(
            json.dumps(identity, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return SecurityEvent(
            event_id=(
                f"network:{action}:{fingerprint}:{observed_at.isoformat()}"
            ),
            source="network.snapshot",
            event_type=f"network.endpoint_{action}",
            timestamp=observed_at,
            process_id=connection.pid,
            details={
                "protocol": connection.protocol,
                "local_address": connection.local_address,
                "local_port": connection.local_port,
                "remote_address": connection.remote_address,
                "remote_port": connection.remote_port,
                "status": connection.status,
                "process_name": connection.process_name,
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
        network_monitor: NetworkDeltaMonitor | None = None,
        event_log_collector: WindowsEventLogCollector | None = None,
    ) -> None:
        self.store = store
        self.process_monitor = process_monitor or ProcessDeltaMonitor()
        self.network_monitor = network_monitor or NetworkDeltaMonitor()
        self.event_log_collector = event_log_collector or WindowsEventLogCollector()

    def collect_once(self) -> MonitorCycle:
        process_result = self.process_monitor.collect()
        network_result = self.network_monitor.collect()
        event_log_result = self.event_log_collector.collect(self.store)
        events = (
            process_result.data
            + network_result.data
            + list(event_log_result.events)
        )
        stored = self.store.persist_batch(events, event_log_result.checkpoints)
        self.process_monitor.commit()
        self.network_monitor.commit()
        pruned = self.store.prune()
        return MonitorCycle(
            observed_events=len(events),
            stored_events=stored,
            pruned_events=pruned,
            errors=(
                process_result.errors
                + network_result.errors
                + event_log_result.errors
            ),
        )
