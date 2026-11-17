import argparse
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from sentinel import cli
from sentinel.models import (
    CollectionResult,
    NetworkConnection,
    ProcessInfo,
    SecurityEvent,
    SystemSnapshot,
)
from sentinel.storage import EventStore


def test_positive_float_rejects_non_finite_values() -> None:
    for value in ("nan", "inf", "-inf"):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.positive_float(value)


class FakeSystemCollector:
    def collect(self):
        return CollectionResult(
            data=SystemSnapshot(
                hostname="TEST-HOST",
                operating_system="Windows",
                os_version="Test Version",
                cpu_percent=17.0,
                memory_percent=42.0,
                disk_percent=25.0,
                process_count=183,
            )
        )


class FakeNetworkCollector:
    def collect(self):
        return CollectionResult(
            data=[
                NetworkConnection(
                    protocol="TCP",
                    local_address="127.0.0.1",
                    local_port=50000,
                    remote_address="127.0.0.1",
                    remote_port=443,
                    status="ESTABLISHED",
                    pid=42,
                    process_name="browser.exe",
                )
            ]
        )


class FakeProcessCollector:
    def collect(self):
        return CollectionResult(
            data=[
                ProcessInfo(
                    pid=42,
                    parent_pid=1,
                    name="python.exe",
                    path="C:\\Python\\python.exe",
                    username="TEST\\user",
                    started_at=None,
                    cpu_percent=3.1,
                    memory_mb=62.0,
                    command_line=("python.exe",),
                )
            ]
        )


def test_status_command_shows_health(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "SystemCollector", FakeSystemCollector)
    monkeypatch.setattr(cli, "NetworkCollector", FakeNetworkCollector)

    exit_code = cli.main(["status"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "SENTINEL SYSTEM STATUS" in output
    assert "TEST-HOST" in output
    assert "HEALTHY" in output
    assert "Not enabled" in output


def test_processes_command_accepts_limit(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "ProcessCollector", FakeProcessCollector)

    exit_code = cli.main(["processes", "--limit", "1"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "SENTINEL PROCESSES" in output
    assert "python.exe" in output
    assert "Displayed: 1" in output


def test_monitor_command_can_run_one_cycle(monkeypatch, capsys, tmp_path) -> None:
    class FakeMonitor:
        def __init__(self, store) -> None:
            pass

        def collect_once(self):
            return SimpleNamespace(stored_events=2, pruned_events=0, errors=())

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "SentinelMonitor", FakeMonitor)

    exit_code = cli.main(
        ["monitor", "--database", str(tmp_path / "events.db"), "--once"]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "2 new event(s)" in output


def test_events_command_reads_local_history(monkeypatch, capsys, tmp_path) -> None:
    database = tmp_path / "events.db"
    EventStore(database).add_events(
        [
            SecurityEvent(
                event_id="test:1",
                source="test",
                event_type="process.started",
                timestamp=datetime.now(UTC),
                process_id=42,
                details={
                    "name": "sample.exe",
                    "path": r"C:\Apps\sample.exe",
                },
            ),
            SecurityEvent(
                event_id="sysmon:13",
                source="Microsoft-Windows-Sysmon/Operational",
                event_type="system.autostart_registry_changed",
                timestamp=datetime.now(UTC),
                process_id=43,
                details={
                    "registry_path": (
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Sample"
                    )
                },
            ),
        ]
    )
    monkeypatch.chdir(tmp_path)

    exit_code = cli.main(["events", "--database", str(database)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "process.started" in output
    assert "sample.exe" in output
    assert r"C:\Apps\sample.exe" in output
    assert r"CurrentVersion\Run\Sample" in output
