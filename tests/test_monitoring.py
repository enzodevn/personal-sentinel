from datetime import UTC, datetime

from sentinel.models import CollectionError, CollectionResult, ProcessInfo
from sentinel.monitoring import ProcessDeltaMonitor


class FakeProcessCollector:
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
