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
import math
import sqlite3
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.collectors.network import NetworkCollector
from sentinel.collectors.processes import ProcessCollector
from sentinel.collectors.system import SystemCollector
from sentinel.logging_config import configure_logging
from sentinel.models import CollectionError, NetworkConnection, ProcessInfo
from sentinel.monitoring import SentinelMonitor
from sentinel.storage import EventStore


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
    monitor = subparsers.add_parser(
        "monitor",
        help="continuously collect local telemetry into SQLite",
    )
    monitor.add_argument(
        "--database",
        type=Path,
        default=Path("data") / "sentinel.db",
        help="local SQLite database path (default: data/sentinel.db)",
    )
    monitor.add_argument(
        "--interval",
        type=positive_float,
        default=5.0,
        help="seconds between collection cycles (default: 5)",
    )
    monitor.add_argument(
        "--retention-days",
        type=positive_integer,
        default=30,
        help="delete events older than this many days (default: 30)",
    )
    monitor.add_argument(
        "--once",
        action="store_true",
        help="run one collection cycle and exit",
    )
    events = subparsers.add_parser("events", help="show recent locally stored events")
    events.add_argument(
        "--database",
        type=Path,
        default=Path("data") / "sentinel.db",
        help="local SQLite database path (default: data/sentinel.db)",
    )
    events.add_argument(
        "--limit",
        type=positive_integer,
        default=20,
        help="maximum number of events to show (default: 20)",
    )
    return parser


def positive_integer(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number greater than zero") from error
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(verbose=args.verbose)

    handlers = {
        "status": show_status,
        "processes": lambda: show_processes(args.limit),
        "network": lambda: show_network(args.limit),
        "monitor": lambda: show_monitor(
            args.database,
            interval=args.interval,
            retention_days=args.retention_days,
            once=args.once,
        ),
        "events": lambda: show_events(args.database, args.limit),
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


def show_monitor(
    database: Path,
    *,
    interval: float = 5.0,
    retention_days: int = 30,
    once: bool = False,
) -> int:
    try:
        store = EventStore(database, retention_days=retention_days)
        monitor = SentinelMonitor(store)
        print(f"Monitoring local telemetry into {database} (Ctrl+C to stop).")
        reported_sources: set[str] = set()
        while True:
            cycle = monitor.collect_once()
            print(
                f"Cycle: {cycle.stored_events} new event(s), "
                f"{cycle.pruned_events} expired event(s) removed."
            )
            new_errors = [
                error for error in cycle.errors if error.scope not in reported_sources
            ]
            _report_errors(new_errors)
            reported_sources.update(error.scope for error in new_errors)
            if once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    except (OSError, sqlite3.Error, RuntimeError) as error:
        LOGGER.exception("monitoring failed")
        print(f"Monitoring failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


def show_events(database: Path, limit: int = 20) -> int:
    try:
        events = EventStore(database).recent_events(limit)
    except (OSError, sqlite3.Error, RuntimeError) as error:
        LOGGER.exception("event history could not be read")
        print(f"Could not read event history: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    print("SENTINEL EVENTS")
    print(f"Displayed: {len(events)}")
    print()
    rows = [
        (
            event.timestamp.isoformat(timespec="seconds"),
            event.event_type,
            _value(event.process_id),
            _clip(
                str(
                    event.details.get("name")
                    or event.details.get("image")
                    or event.details.get("process_name")
                    or ""
                ),
                32,
            ),
            _clip(_event_detail(event.details), 64),
            event.source,
        )
        for event in events
    ]
    _print_table(
        ("TIME (UTC)", "EVENT", "PID", "PROCESS", "DETAILS", "SOURCE"),
        rows,
    )
    return 0


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


def _event_detail(details: Mapping[str, object]) -> str:
    registry_path = details.get("registry_path")
    if registry_path:
        return str(registry_path)
    local_address = details.get("local_address")
    if local_address:
        local_port = details.get("local_port")
        local = _endpoint(
            str(local_address),
            local_port if isinstance(local_port, int) else None,
        )
        remote_address = details.get("remote_address")
        remote_port = details.get("remote_port")
        remote = (
            _endpoint(
                str(remote_address),
                remote_port if isinstance(remote_port, int) else None,
            )
            if remote_address
            else "no remote peer"
        )
        protocol = str(details.get("protocol") or "")
        status = str(details.get("status") or "")
        return " ".join(part for part in (protocol, local, "->", remote, status) if part)
    destination_ip = details.get("destination_ip")
    if destination_ip:
        destination_port = details.get("destination_port")
        endpoint = str(destination_ip)
        if destination_port is not None:
            endpoint = f"{endpoint}:{destination_port}"
        protocol = details.get("protocol")
        return f"{protocol} {endpoint}" if protocol else endpoint
    for key in ("path", "parent_image", "provider"):
        value = details.get(key)
        if value:
            return str(value)
    return "-"


if __name__ == "__main__":
    raise SystemExit(main())
