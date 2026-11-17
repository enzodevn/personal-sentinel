from datetime import UTC, datetime

from sentinel.models import (
    CollectionError,
    CollectionResult,
    NetworkConnection,
    ProcessInfo,
    SecurityEvent,
)
from sentinel.monitoring import (
    NetworkDeltaMonitor,
    ProcessDeltaMonitor,
    SentinelMonitor,
)
from sentinel.windows_events import WindowsEventBatch


class FakeProcessCollector:
    def __init__(self, results) -> None:
        self.results = iter(results)

    def collect(self):
        return next(self.results)


class FakeNetworkCollector:
    def __init__(self, results) -> None:
        self.results = iter(results)

    def collect(self):
        return next(self.results)


def process(pid: int, started_at: datetime, name: str) -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        parent_pid=1,
        name=name,
        path=f"C:\\Apps\\{name}",
        username=None,
        started_at=started_at,
        cpu_percent=0.0,
        memory_mb=1.0,
        command_line=(),
    )


def connection(
    local_port: int,
    *,
    remote_address: str | None = "198.51.100.10",
    remote_port: int | None = 443,
    status: str = "ESTABLISHED",
    pid: int | None = 42,
) -> NetworkConnection:
    return NetworkConnection(
        protocol="TCP",
        local_address="192.0.2.10",
        local_port=local_port,
        remote_address=remote_address,
        remote_port=remote_port,
        status=status,
        pid=pid,
        process_name="browser.exe",
    )


def test_process_delta_monitor_emits_start_and_exit_after_baseline() -> None:
    started_at = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    first = process(10, started_at, "first.exe")
    second = process(20, started_at, "second.exe")
    monitor = ProcessDeltaMonitor(
        FakeProcessCollector(
            [
                CollectionResult(data=[first]),
                CollectionResult(data=[first, second]),
                CollectionResult(data=[second]),
            ]
        )
    )

    assert monitor.collect().data == []
    monitor.commit()
    started = monitor.collect().data
    monitor.commit()
    exited = monitor.collect().data

    assert [(item.event_type, item.process_id) for item in started] == [
        ("process.started", 20)
    ]
    assert [(item.event_type, item.process_id) for item in exited] == [
        ("process.exited", 10)
    ]
    assert "command_line" not in started[0].details


def test_process_delta_monitor_does_not_infer_exit_for_inaccessible_process() -> None:
    started_at = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    observed = process(10, started_at, "observed.exe")
    inaccessible = CollectionError(
        scope="process.pid.10",
        error_type="AccessDenied",
        message="denied",
    )
    monitor = ProcessDeltaMonitor(
        FakeProcessCollector(
            [
                CollectionResult(data=[observed]),
                CollectionResult(data=[], errors=(inaccessible,)),
                CollectionResult(data=[observed]),
            ]
        )
    )

    assert monitor.collect().data == []
    monitor.commit()
    assert monitor.collect().data == []
    monitor.commit()
    assert monitor.collect().data == []
    monitor.commit()


def test_process_delta_monitor_requires_persist_commit_before_advancing() -> None:
    started_at = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    first = process(10, started_at, "first.exe")
    second = process(20, started_at, "second.exe")
    monitor = ProcessDeltaMonitor(
        FakeProcessCollector(
            [
                CollectionResult(data=[first]),
                CollectionResult(data=[first, second]),
                CollectionResult(data=[first, second]),
            ]
        )
    )

    monitor.collect()
    monitor.commit()
    assert monitor.collect().data[0].process_id == 20
    retry = monitor.collect().data

    assert [item.process_id for item in retry] == [20]


def test_network_delta_monitor_emits_endpoint_changes_and_ignores_state_updates() -> None:
    first = connection(50000)
    same_endpoint_new_state = connection(50000, status="SYN_SENT")
    second = connection(50001)
    monitor = NetworkDeltaMonitor(
        FakeNetworkCollector(
            [
                CollectionResult(data=[first]),
                CollectionResult(data=[same_endpoint_new_state, second]),
                CollectionResult(data=[second]),
            ]
        )
    )

    assert monitor.collect().data == []
    monitor.commit()
    opened = monitor.collect().data
    monitor.commit()
    closed = monitor.collect().data

    assert [(event.event_type, event.process_id) for event in opened] == [
        ("network.endpoint_opened", 42)
    ]
    assert opened[0].details["local_port"] == 50001
    assert [(event.event_type, event.process_id) for event in closed] == [
        ("network.endpoint_closed", 42)
    ]


def test_network_delta_monitor_tracks_tcp_owner_during_close_states() -> None:
    observed = connection(50000)
    fin_wait = connection(50000, status="FIN_WAIT1", pid=0)
    last_ack = connection(50000, status="LAST_ACK", pid=0)
    time_wait = connection(50000, status="TIME_WAIT", pid=0)
    closed = connection(50000, status="CLOSE", pid=0)
    monitor = NetworkDeltaMonitor(
        FakeNetworkCollector(
            [
                CollectionResult(data=[observed]),
                CollectionResult(data=[fin_wait]),
                CollectionResult(data=[last_ack]),
                CollectionResult(data=[time_wait]),
                CollectionResult(data=[closed]),
            ]
        )
    )

    assert monitor.collect().data == []
    monitor.commit()
    events = monitor.collect().data

    assert [(event.event_type, event.process_id) for event in events] == [
        ("network.endpoint_closed", 42)
    ]
    monitor.commit()
    assert monitor.collect().data == []
    monitor.commit()
    assert monitor.collect().data == []
    monitor.commit()
    assert monitor.collect().data == []


def test_network_delta_monitor_does_not_infer_closure_from_incomplete_snapshot() -> None:
    observed = connection(50000)
    malformed_row = CollectionError(
        scope="network.connection.1",
        error_type="ValueError",
        message="invalid socket row",
    )
    monitor = NetworkDeltaMonitor(
        FakeNetworkCollector(
            [
                CollectionResult(data=[observed]),
                CollectionResult(data=[], errors=(malformed_row,)),
                CollectionResult(data=[]),
            ]
        )
    )

    assert monitor.collect().data == []
    monitor.commit()
    assert monitor.collect().data == []
    monitor.commit()
    closed = monitor.collect().data

    assert [event.event_type for event in closed] == ["network.endpoint_closed"]


def test_network_delta_monitor_keeps_state_after_enumeration_failure() -> None:
    observed = connection(50000)
    denied = CollectionError(
        scope="network.enumeration",
        error_type="AccessDenied",
        message="denied",
    )
    monitor = NetworkDeltaMonitor(
        FakeNetworkCollector(
            [
                CollectionResult(data=[observed]),
                CollectionResult(data=[], errors=(denied,)),
                CollectionResult(data=[]),
            ]
        )
    )

    assert monitor.collect().data == []
    monitor.commit()
    assert monitor.collect().data == []
    monitor.commit()
    closed = monitor.collect().data

    assert [event.event_type for event in closed] == ["network.endpoint_closed"]


def test_sentinel_monitor_persists_network_events_before_committing_state() -> None:
    event = SecurityEvent(
        event_id="network:test",
        source="network.snapshot",
        event_type="network.endpoint_opened",
        timestamp=datetime.now(UTC),
        process_id=42,
        details={"local_port": 50000},
    )

    class FakeDeltaMonitor:
        def __init__(self, events, actions) -> None:
            self.events = events
            self.actions = actions

        def collect(self):
            return CollectionResult(data=self.events)

        def commit(self):
            self.actions.append("commit")

    class FakeStore:
        def __init__(self, actions) -> None:
            self.events = []
            self.actions = actions

        def persist_batch(self, events, checkpoints):
            self.actions.append("persist")
            self.events.extend(events)
            return len(events)

        def prune(self):
            return 0

    class FakeEventLogCollector:
        def collect(self, store):
            return WindowsEventBatch(events=(), checkpoints={}, errors=())

    actions = []
    process_monitor = FakeDeltaMonitor([], actions)
    network_monitor = FakeDeltaMonitor([event], actions)
    store = FakeStore(actions)
    monitor = SentinelMonitor(
        store,
        process_monitor=process_monitor,
        network_monitor=network_monitor,
        event_log_collector=FakeEventLogCollector(),
    )

    cycle = monitor.collect_once()

    assert cycle.stored_events == 1
    assert store.events == [event]
    assert actions == ["persist", "commit", "commit"]
