from sentinel import cli
from sentinel.models import (
    CollectionResult,
    NetworkConnection,
    ProcessInfo,
    SystemSnapshot,
)


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
