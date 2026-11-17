"""Local SQLite storage for normalized telemetry events and source checkpoints."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinel.models import SecurityEvent


SCHEMA_VERSION = 1


class EventStore:
    """Persist bounded, deduplicated telemetry in a local SQLite database."""

    def __init__(
        self,
        path: str | Path,
        *,
        retention_days: int = 30,
        max_events: int = 100_000,
    ) -> None:
        if retention_days <= 0:
            raise ValueError("retention_days must be greater than zero")
        if max_events <= 0:
            raise ValueError("max_events must be greater than zero")

        self.path = Path(path)
        self.retention_days = retention_days
        self.max_events = max_events
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def persist_batch(
        self,
        events: list[SecurityEvent],
        checkpoints: Mapping[str, int] | None = None,
    ) -> int:
        """Atomically store events and advance source checkpoints."""
        rows = [
            (
                event.event_id,
                event.source,
                event.event_type,
                event.timestamp.astimezone(UTC).isoformat(),
                event.process_id,
                json.dumps(dict(event.details), ensure_ascii=True, sort_keys=True),
            )
            for event in events
        ]
        with self._connect() as connection:
            inserted = 0
            if rows:
                cursor = connection.executemany(
                    """
                    INSERT OR IGNORE INTO events
                        (event_id, source, event_type, timestamp, process_id, details_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                inserted = cursor.rowcount
            if checkpoints:
                for source, record_id in checkpoints.items():
                    if record_id < 0:
                        raise ValueError("record_id must be non-negative")
                    connection.execute(
                        """
                        INSERT INTO source_checkpoints (source, record_id)
                        VALUES (?, ?)
                        ON CONFLICT(source) DO UPDATE SET record_id = excluded.record_id
                        """,
                        (source, record_id),
                    )
            return inserted

    def add_events(self, events: list[SecurityEvent]) -> int:
        """Insert events once by stable event ID and return the inserted count."""

        return self.persist_batch(events)

    def recent_events(self, limit: int = 50) -> list[SecurityEvent]:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT event_id, source, event_type, timestamp, process_id, details_json
                FROM events
                ORDER BY timestamp DESC, event_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            SecurityEvent(
                event_id=row["event_id"],
                source=row["source"],
                event_type=row["event_type"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                process_id=row["process_id"],
                details=json.loads(row["details_json"]),
            )
            for row in rows
        ]

    def prune(self, now: datetime | None = None) -> int:
        """Apply age and row-count retention limits, returning rows removed."""

        current_time = now or datetime.now(UTC)
        if not current_time.tzinfo or current_time.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        cutoff = (
            current_time.astimezone(UTC) - timedelta(days=self.retention_days)
        ).isoformat()
        with self._connect() as connection:
            expired = connection.execute(
                "DELETE FROM events WHERE timestamp < ?",
                (cutoff,),
            ).rowcount
            excess = connection.execute(
                """
                DELETE FROM events
                WHERE event_id IN (
                    SELECT event_id FROM events
                    ORDER BY timestamp DESC, event_id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (self.max_events,),
            ).rowcount
            return expired + excess

    def get_checkpoint(self, source: str) -> int | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_id FROM source_checkpoints WHERE source = ?",
                (source,),
            ).fetchone()
        return None if row is None else int(row["record_id"])

    def set_checkpoint(self, source: str, record_id: int) -> None:
        if record_id < 0:
            raise ValueError("record_id must be non-negative")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO source_checkpoints (source, record_id)
                VALUES (?, ?)
                ON CONFLICT(source) DO UPDATE SET record_id = excluded.record_id
                """,
                (source, record_id),
            )

    def _initialize(self) -> None:
        with self._connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database schema {version} is newer than supported schema "
                    f"{SCHEMA_VERSION}."
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    process_id INTEGER,
                    details_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp
                    ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_source_type
                    ON events(source, event_type);
                CREATE TABLE IF NOT EXISTS source_checkpoints (
                    source TEXT PRIMARY KEY,
                    record_id INTEGER NOT NULL CHECK(record_id >= 0)
                );
                """
            )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()
