"""Collect current local Internet socket information.

PURPOSE: Associate local/remote addresses and ports with owning processes.
WHAT IT TEACHES: TCP, UDP, sockets, endpoints, connection state, and privileges.
CAREER VALUE: Network telemetry supports SOC investigations and observability.
SYSTEM VALUE: Supplies raw process-to-network context without blocking traffic.
CURRENT NECESSITY: HIGH for V0.1; enrichment such as DNS is intentionally deferred.
"""

from __future__ import annotations

import socket
from typing import Any

import psutil

from sentinel.models import CollectionError, CollectionResult, NetworkConnection


class NetworkCollector:
    """Read IPv4/IPv6 TCP and UDP endpoints without changing firewall state."""

    def collect(self) -> CollectionResult[list[NetworkConnection]]:
        errors: list[CollectionError] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception as error:  # AccessDenied can affect the whole table.
            errors.append(CollectionError.from_exception("network.enumeration", error))
            return CollectionResult(data=[], errors=tuple(errors))

        process_names: dict[int, str | None] = {}
        snapshots: list[NetworkConnection] = []
        for index, connection in enumerate(connections):
            try:
                process_name = self._process_name(connection.pid, process_names, errors)
                local_address, local_port = self._split_address(connection.laddr)
                remote_address, remote_port = self._split_address(connection.raddr)
                protocol = "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
                status = connection.status or "NONE"

                snapshots.append(
                    NetworkConnection(
                        protocol=protocol,
                        local_address=local_address,
                        local_port=local_port,
                        remote_address=remote_address,
                        remote_port=remote_port,
                        status=status,
                        pid=connection.pid,
                        process_name=process_name,
                    )
                )
            except Exception as error:  # One malformed row must not hide the table.
                errors.append(
                    CollectionError.from_exception(f"network.connection.{index}", error)
                )

        snapshots.sort(
            key=lambda item: (
                item.protocol,
                item.local_address or "",
                item.local_port or -1,
                item.pid or -1,
            )
        )
        return CollectionResult(data=snapshots, errors=tuple(errors))

    @staticmethod
    def _split_address(address: Any) -> tuple[str | None, int | None]:
        if not address:
            return None, None
        if hasattr(address, "ip"):
            return str(address.ip), int(address.port)
        return str(address[0]), int(address[1])

    @staticmethod
    def _process_name(
        pid: int | None,
        cache: dict[int, str | None],
        errors: list[CollectionError],
    ) -> str | None:
        if pid is None:
            return None
        if pid in cache:
            return cache[pid]
        try:
            cache[pid] = psutil.Process(pid).name()
        except Exception as error:  # Process ownership is optional enrichment.
            cache[pid] = None
            errors.append(CollectionError.from_exception(f"network.pid.{pid}", error))
        return cache[pid]
