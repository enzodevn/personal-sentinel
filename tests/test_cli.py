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
from sentinel.detection.engine import DetectionEngine
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
        def __init__(self, store, **kwargs) -> None:
            pass

        def collect_once(self):
            return SimpleNamespace(
                stored_events=2,
                stored_detections=1,
                pruned_events=0,
                pruned_detections=0,
                errors=(),
            )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "SentinelMonitor", FakeMonitor)

    exit_code = cli.main(
        ["monitor", "--database", str(tmp_path / "events.db"), "--once"]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "2 new event(s)" in output
    assert "1 new alert(s)" in output


def test_monitor_command_loads_local_sigma_rules(monkeypatch, capsys, tmp_path) -> None:
    class FakeMonitor:
        def __init__(self, store, **kwargs) -> None:
            pass

        def collect_once(self):
            return SimpleNamespace(
                stored_events=0,
                stored_detections=0,
                pruned_events=0,
                pruned_detections=0,
                errors=(),
            )

    rule_file = tmp_path / "rule.yml"
    rule_file.write_text(
        r"""
title: Local process rule
id: 11111111-2222-4333-8444-555555555555
status: test
description: A local test detection.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    Image|endswith: '\cmd.exe'
  condition: selection
level: high
date: 2026-11-18
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "SentinelMonitor", FakeMonitor)

    exit_code = cli.main(
        [
            "monitor",
            "--database",
            str(tmp_path / "events.db"),
            "--sigma-rules",
            str(rule_file),
            "--once",
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Loaded 1 Sigma rule(s)" in output
    assert "Microsoft-Windows-Sysmon/Operational" in output


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
            SecurityEvent(
                event_id="network:opened",
                source="network.snapshot",
                event_type="network.endpoint_opened",
                timestamp=datetime.now(UTC),
                process_id=44,
                details={
                    "protocol": "TCP",
                    "local_address": "192.0.2.10",
                    "local_port": 50000,
                    "remote_address": "198.51.100.10",
                    "remote_port": 443,
                    "status": "ESTABLISHED",
                    "process_name": "browser.exe",
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
    assert "198.51.100.10:443" in output
    assert "browser.exe" in output


def test_alerts_command_explains_stored_findings(monkeypatch, capsys, tmp_path) -> None:
    database = tmp_path / "events.db"
    record = SecurityEvent(
        event_id="sys:7045:1",
        source="System",
        event_type="system.service_installed",
        timestamp=datetime(2026, 11, 17, 12, 0, tzinfo=UTC),
        process_id=None,
        source_event_id=7045,
        details={"service_name": "ExampleService", "start_type": "auto"},
    )
    detection = DetectionEngine().evaluate([record])[0]
    EventStore(database).persist_cycle([record], [detection])
    monkeypatch.chdir(tmp_path)

    exit_code = cli.main(["alerts", "--database", str(database)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert detection.name in output
    assert "Why:" in output
    assert "EventID=7045" in output
    assert "ExampleService" in output
