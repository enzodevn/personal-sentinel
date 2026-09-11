import socket
from collections import namedtuple

import psutil

from sentinel.collectors import network


Address = namedtuple("Address", "ip port")
Connection = namedtuple("Connection", "type laddr raddr status pid")


class FakeOwner:
    def name(self) -> str:
        return "browser.exe"


def test_network_collector_correlates_connection_and_process(monkeypatch) -> None:
    connection = Connection(
        type=socket.SOCK_STREAM,
        laddr=Address("127.0.0.1", 50123),
        raddr=Address("127.0.0.1", 443),
        status="ESTABLISHED",
        pid=42,
    )
    monkeypatch.setattr(network.psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(network.psutil, "Process", lambda pid: FakeOwner())

    result = network.NetworkCollector().collect()

    assert result.ok
    assert result.data[0].protocol == "TCP"
    assert result.data[0].remote_port == 443
    assert result.data[0].pid == 42
    assert result.data[0].process_name == "browser.exe"


def test_network_collector_reports_enumeration_failure(monkeypatch) -> None:
    def denied(kind):
        raise psutil.AccessDenied(pid=None)

    monkeypatch.setattr(network.psutil, "net_connections", denied)

    result = network.NetworkCollector().collect()

    assert result.data == []
    assert result.errors[0].scope == "network.enumeration"
