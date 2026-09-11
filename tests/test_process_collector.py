from types import SimpleNamespace

import psutil

from sentinel.collectors import processes


class FakeProcess:
    def __init__(self, info, cpu_values=(0.0, 2.5)) -> None:
        self.info = info
        self.pid = info["pid"]
        self._cpu_values = iter(cpu_values)

    def cpu_percent(self, interval=None):
        return next(self._cpu_values)


class DeniedProcess(FakeProcess):
    def cpu_percent(self, interval=None):
        raise psutil.AccessDenied(pid=self.pid)


def process_info(pid: int, ppid: int, name: str):
    return {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "exe": f"C:\\Apps\\{name}",
        "username": "TEST\\user",
        "create_time": 1_700_000_000.0,
        "memory_info": SimpleNamespace(rss=10 * 1024 * 1024),
        "cmdline": [name, "--safe-test"],
    }


def test_process_collector_builds_parent_context(monkeypatch) -> None:
    parent = FakeProcess(process_info(10, 1, "parent.exe"))
    child = FakeProcess(process_info(20, 10, "child.exe"))
    monkeypatch.setattr(
        processes.psutil,
        "process_iter",
        lambda attrs, ad_value: [child, parent],
    )

    result = processes.ProcessCollector(cpu_sample_seconds=0).collect()

    assert result.ok
    assert [item.pid for item in result.data] == [10, 20]
    assert result.data[1].parent_name == "parent.exe"
    assert result.data[1].memory_mb == 10.0
    assert result.data[1].command_line == ("child.exe", "--safe-test")


def test_process_collector_skips_inaccessible_process(monkeypatch) -> None:
    allowed = FakeProcess(process_info(10, 1, "allowed.exe"))
    denied = DeniedProcess(process_info(20, 1, "denied.exe"))
    monkeypatch.setattr(
        processes.psutil,
        "process_iter",
        lambda attrs, ad_value: [allowed, denied],
    )

    result = processes.ProcessCollector(cpu_sample_seconds=0).collect()

    assert [item.pid for item in result.data] == [10]
    assert result.errors[0].scope == "process.pid.20"
