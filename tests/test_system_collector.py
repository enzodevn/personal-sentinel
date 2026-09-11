from types import SimpleNamespace

from sentinel.collectors import system


def test_system_collector_returns_expected_metrics(monkeypatch) -> None:
    observed_disk_paths = []
    monkeypatch.setattr(system.psutil, "cpu_percent", lambda interval: 12.5)
    monkeypatch.setattr(
        system.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(percent=41.0),
    )
    monkeypatch.setattr(
        system.psutil,
        "disk_usage",
        lambda path: observed_disk_paths.append(path) or SimpleNamespace(percent=63.25),
    )
    monkeypatch.setattr(system.psutil, "pids", lambda: [1, 2, 3])
    monkeypatch.setattr(system.socket, "gethostname", lambda: "TEST-HOST")

    result = system.SystemCollector(cpu_sample_seconds=0).collect()

    assert result.ok
    assert result.data.hostname == "TEST-HOST"
    assert result.data.cpu_percent == 12.5
    assert result.data.memory_percent == 41.0
    assert result.data.disk_percent == 63.25
    assert result.data.process_count == 3
    assert isinstance(observed_disk_paths[0], str)


def test_system_collector_keeps_other_metrics_when_one_fails(monkeypatch) -> None:
    def fail_memory():
        raise OSError("memory unavailable")

    monkeypatch.setattr(system.psutil, "cpu_percent", lambda interval: 5.0)
    monkeypatch.setattr(system.psutil, "virtual_memory", fail_memory)
    monkeypatch.setattr(
        system.psutil,
        "disk_usage",
        lambda path: SimpleNamespace(percent=10.0),
    )
    monkeypatch.setattr(system.psutil, "pids", lambda: [1])

    result = system.SystemCollector(cpu_sample_seconds=0).collect()

    assert result.data.cpu_percent == 5.0
    assert result.data.memory_percent is None
    assert result.data.process_count == 1
    assert result.errors[0].scope == "system.memory"
