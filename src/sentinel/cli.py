"""Human-readable command-line interface for Sentinel V0.1.

PURPOSE: Make local telemetry inspectable without a server or dashboard.
WHAT IT TEACHES: CLI design, composition, output contracts, and exit codes.
CAREER VALUE: Operational and security tooling often begins with a reliable CLI.
SYSTEM VALUE: Connects collectors to the user while keeping UI logic separate.
CURRENT NECESSITY: HIGH; it is the V0.1 interaction surface.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from typing import Any

from sentinel import __version__
from sentinel.collectors.network import NetworkCollector
from sentinel.collectors.processes import ProcessCollector
from sentinel.collectors.system import SystemCollector
from sentinel.logging_config import configure_logging
from sentinel.models import CollectionError, NetworkConnection, ProcessInfo


LOGGER = logging.getLogger("sentinel.cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Local, read-only Windows system observer.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="write DEBUG-level application logs",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="show a concise system health snapshot")

    processes = subparsers.add_parser("processes", help="list running processes")
    processes.add_argument(
        "--limit",
        type=positive_integer,
        help="show at most this many rows",
    )

    network = subparsers.add_parser("network", help="list current network endpoints")
    network.add_argument(
        "--limit",
        type=positive_integer,
        help="show at most this many rows",
    )
    return parser


def positive_integer(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(verbose=args.verbose)

    handlers = {
        "status": show_status,
        "processes": lambda: show_processes(args.limit),
        "network": lambda: show_network(args.limit),
    }
    return handlers[args.command]()


def show_status() -> int:
    system_result = SystemCollector().collect()
    network_result = NetworkCollector().collect()
    snapshot = system_result.data
    all_errors = system_result.errors + network_result.errors
    health = "HEALTHY" if not all_errors else "DEGRADED"
    established_connections: int | None
    if network_result.errors and not network_result.data:
        established_connections = None
    else:
        established_connections = sum(
            connection.protocol == "TCP" and connection.status == "ESTABLISHED"
            for connection in network_result.data
        )

    rows = [
        ("Host", snapshot.hostname),
        ("OS", f"{snapshot.operating_system} {snapshot.os_version}"),
        ("CPU", _percent(snapshot.cpu_percent)),
        ("Memory", _percent(snapshot.memory_percent)),
        ("Storage", _percent(snapshot.disk_percent)),
        ("Processes", _value(snapshot.process_count)),
        ("Active network connections", _value(established_connections)),
        ("Security Engine", "Not enabled"),
        ("Monitoring", "Manual"),
        ("Status", health),
    ]

    print("SENTINEL SYSTEM STATUS")
    print()
    _print_key_values(rows)
    _report_errors(all_errors)
    return 0


def show_processes(limit: int | None = None) -> int:
    result = ProcessCollector().collect()
    processes = _limited(result.data, limit)
    rows = [
        (
            process.pid,
            _value(process.parent_pid),
            _number(process.cpu_percent),
            _number(process.memory_mb),
            _clip(process.username, 22),
            _clip(process.name, 26),
            _clip(process.path, 54),
        )
        for process in processes
    ]
    print("SENTINEL PROCESSES")
    print(f"Collected: {len(result.data)} | Displayed: {len(rows)}")
    print()
    _print_table(
        ("PID", "PPID", "CPU%", "MEM MB", "USER", "NAME", "EXECUTABLE"),
        rows,
    )
    _report_errors(result.errors)
    return 1 if result.errors and not result.data else 0


def show_network(limit: int | None = None) -> int:
    result = NetworkCollector().collect()
    connections = _limited(result.data, limit)
    rows = [
        (
            connection.protocol,
            _endpoint(connection.local_address, connection.local_port),
            _endpoint(connection.remote_address, connection.remote_port),
            connection.status,
            _value(connection.pid),
            _clip(connection.process_name, 28),
        )
        for connection in connections
    ]
    print("SENTINEL NETWORK")
    print(f"Collected: {len(result.data)} | Displayed: {len(rows)}")
    print()
    _print_table(
        ("PROTO", "LOCAL", "REMOTE", "STATUS", "PID", "PROCESS"),
        rows,
    )
    _report_errors(result.errors)
    return 1 if result.errors and not result.data else 0


def _report_errors(errors: Sequence[CollectionError]) -> None:
    if not errors:
        return
    print(file=sys.stderr)
    print(f"Warnings: {len(errors)} collection issue(s).", file=sys.stderr)
    for error in errors[:5]:
        print(
            f"- {error.scope}: {error.error_type}: {error.message}",
            file=sys.stderr,
        )
    if len(errors) > 5:
        print(f"- ... and {len(errors) - 5} more", file=sys.stderr)
    LOGGER.warning("collection completed with %d warning(s)", len(errors))


def _print_key_values(rows: Sequence[tuple[str, Any]]) -> None:
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        print(f"{label:<{width}} : {value}")


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> None:
    if not rows:
        print("No data available.")
        return
    text_rows = [[str(cell) for cell in row] for row in rows]
    widths = [
        max(len(header), *(len(row[index]) for row in text_rows))
        for index, header in enumerate(headers)
    ]
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in text_rows:
        print("  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))


def _limited(items: list[Any], limit: int | None) -> list[Any]:
    return items if limit is None else items[:limit]


def _endpoint(address: str | None, port: int | None) -> str:
    if address is None:
        return "-"
    separator = "]:" if ":" in address else ":"
    prefix = "[" if ":" in address else ""
    return f"{prefix}{address}{separator}{port}" if port is not None else address


def _value(value: object | None) -> str:
    return "Unavailable" if value is None else str(value)


def _number(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def _percent(value: float | None) -> str:
    return "Unavailable" if value is None else f"{value:.1f}%"


def _clip(value: str | None, width: int) -> str:
    if not value:
        return "-"
    safe = " ".join(value.splitlines())
    return safe if len(safe) <= width else f"{safe[: width - 3]}..."


if __name__ == "__main__":
    raise SystemExit(main())
