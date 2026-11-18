"""Local SQLite storage for normalized telemetry events and source checkpoints."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinel.detection.models import (
    Detection,
    DetectionEvidence,
    RiskLevel,
    Severity,
)
from sentinel.models import SecurityEvent


SCHEMA_VERSION = 3


class EventStore:
    """Persist bounded, deduplicated telemetry in a local SQLite database."""

    def __init__(
        self,
        path: str | Path,
        *,
        retention_days: int = 30,
        max_events: int = 100_000,
        max_detections: int = 20_000,
    ) -> None:
        if retention_days <= 0:
            raise ValueError("retention_days must be greater than zero")
        if max_events <= 0:
            raise ValueError("max_events must be greater than zero")
        if max_detections <= 0:
            raise ValueError("max_detections must be greater than zero")

        self.path = Path(path)
        self.retention_days = retention_days
        self.max_events = max_events
        self.max_detections = max_detections
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def persist_batch(
        self,
        events: list[SecurityEvent],
        checkpoints: Mapping[str, int] | None = None,
    ) -> int:
        """Atomically store events and advance source checkpoints."""
        inserted, _ = self.persist_cycle(events, [], checkpoints)
        return inserted

    def persist_cycle(
        self,
        events: list[SecurityEvent],
        detections: list[Detection],
        checkpoints: Mapping[str, int] | None = None,
    ) -> tuple[int, int]:
        """Atomically store events, detections, and source checkpoints."""
        rows = [
            (
                event.event_id,
                event.source,
                event.event_type,
                event.timestamp.astimezone(UTC).isoformat(),
                event.process_id,
                event.source_event_id,
                json.dumps(dict(event.details), ensure_ascii=True, sort_keys=True),
            )
            for event in events
        ]
        detection_rows = [
            (
                detection.detection_id,
                detection.rule_id,
                detection.rule_version,
                max(
                    evidence.observed_at for evidence in detection.evidence
                ).astimezone(UTC).isoformat(),
                detection.risk_score,
                _serialize_detection(detection),
            )
            for detection in detections
        ]
        with self._connect() as connection:
            inserted = 0
            inserted_detections = 0
            if rows:
                cursor = connection.executemany(
                    """
                    INSERT OR IGNORE INTO events
                        (
                            event_id, source, event_type, timestamp, process_id,
                            source_event_id, details_json
                        )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                inserted = cursor.rowcount
            if detection_rows:
                cursor = connection.executemany(
                    """
                    INSERT OR IGNORE INTO detections
                        (
                            detection_id, rule_id, rule_version, timestamp,
                            risk_score, payload_json
                        )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    detection_rows,
                )
                inserted_detections = cursor.rowcount
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
            return inserted, inserted_detections

    def add_events(self, events: list[SecurityEvent]) -> int:
        """Insert events once by stable event ID and return the inserted count."""

        return self.persist_batch(events)

    def recent_events(self, limit: int = 50) -> list[SecurityEvent]:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    event_id, source, event_type, timestamp, process_id,
                    source_event_id, details_json
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
                source_event_id=row["source_event_id"],
            )
            for row in rows
        ]

    def events_since(
        self,
        since: datetime,
        *,
        limit: int = 5_000,
    ) -> list[SecurityEvent]:
        """Read a bounded chronological window for temporal correlation."""
        if not since.tzinfo or since.utcoffset() is None:
            raise ValueError("since must be timezone-aware")
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    event_id, source, event_type, timestamp, process_id,
                    source_event_id, details_json
                FROM events
                WHERE timestamp >= ?
                ORDER BY timestamp DESC, event_id DESC
                LIMIT ?
                """,
                (since.astimezone(UTC).isoformat(), limit),
            ).fetchall()
        return [
            SecurityEvent(
                event_id=row["event_id"],
                source=row["source"],
                event_type=row["event_type"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                process_id=row["process_id"],
                details=json.loads(row["details_json"]),
                source_event_id=row["source_event_id"],
            )
            for row in reversed(rows)
        ]

    def recent_detections(self, limit: int = 50) -> list[Detection]:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json FROM detections
                ORDER BY timestamp DESC, detection_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_deserialize_detection(row["payload_json"]) for row in rows]

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

    def prune_detections(self, now: datetime | None = None) -> int:
        """Apply age and row-count retention limits to stored detections."""
        current_time = now or datetime.now(UTC)
        if not current_time.tzinfo or current_time.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        cutoff = (
            current_time.astimezone(UTC) - timedelta(days=self.retention_days)
        ).isoformat()
        with self._connect() as connection:
            expired = connection.execute(
                "DELETE FROM detections WHERE timestamp < ?",
                (cutoff,),
            ).rowcount
            excess = connection.execute(
                """
                DELETE FROM detections
                WHERE detection_id IN (
                    SELECT detection_id FROM detections
                    ORDER BY timestamp DESC, detection_id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (self.max_detections,),
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
                    source_event_id INTEGER,
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
                CREATE TABLE IF NOT EXISTS detections (
                    detection_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    rule_version TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    risk_score INTEGER NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_detections_timestamp
                    ON detections(timestamp DESC);
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(events)").fetchall()
            }
            if "source_event_id" not in columns:
                connection.execute(
                    "ALTER TABLE events ADD COLUMN source_event_id INTEGER"
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


def _serialize_detection(detection: Detection) -> str:
    payload = {
        "detection_id": detection.detection_id,
        "rule_id": detection.rule_id,
        "rule_version": detection.rule_version,
        "name": detection.name,
        "description": detection.description,
        "category": detection.category,
        "criteria": detection.criteria,
        "severity": detection.severity.value,
        "confidence": detection.confidence,
        "impact": detection.impact,
        "evidence_quality": detection.evidence_quality,
        "context": detection.context,
        "risk_score": detection.risk_score,
        "risk_level": detection.risk_level.value,
        "evidence": [
            {
                "event_id": evidence.event_id,
                "source": evidence.source,
                "event_type": evidence.event_type,
                "observed_at": evidence.observed_at.isoformat(),
                "process_id": evidence.process_id,
                "source_event_id": evidence.source_event_id,
                "details": dict(evidence.details),
            }
            for evidence in detection.evidence
        ],
        "mitre_techniques": detection.mitre_techniques,
        "recommendations": detection.recommendations,
    }
    return json.dumps(payload, ensure_ascii=True, sort_keys=True)


def _deserialize_detection(payload_json: str) -> Detection:
    payload = json.loads(payload_json)
    evidence = tuple(
        DetectionEvidence(
            event_id=item["event_id"],
            source=item["source"],
            event_type=item["event_type"],
            observed_at=datetime.fromisoformat(item["observed_at"]),
            process_id=item["process_id"],
            source_event_id=item["source_event_id"],
            details=item["details"],
        )
        for item in payload["evidence"]
    )
    return Detection(
        detection_id=payload["detection_id"],
        rule_id=payload["rule_id"],
        rule_version=payload["rule_version"],
        name=payload["name"],
        description=payload["description"],
        category=payload["category"],
        criteria=payload["criteria"],
        severity=Severity(payload["severity"]),
        confidence=payload["confidence"],
        impact=payload["impact"],
        evidence_quality=payload["evidence_quality"],
        context=payload["context"],
        risk_score=payload["risk_score"],
        risk_level=RiskLevel(payload["risk_level"]),
        evidence=evidence,
        mitre_techniques=tuple(payload["mitre_techniques"]),
        recommendations=tuple(payload["recommendations"]),
    )
