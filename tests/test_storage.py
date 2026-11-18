import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from sentinel.detection.engine import DetectionEngine
from sentinel.models import SecurityEvent
from sentinel.storage import EventStore


def event(event_id: str, timestamp: datetime) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        source="test",
        event_type="test.observed",
        timestamp=timestamp,
        process_id=42,
        details={"name": "sample.exe"},
    )


def detected_event(event_id: str, timestamp: datetime) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        source="System",
        event_type="system.service_installed",
        timestamp=timestamp,
        process_id=None,
        source_event_id=7045,
        details={"service_name": "ExampleService", "start_type": "auto"},
    )


def test_event_store_round_trips_and_deduplicates(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    observed_at = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    record = SecurityEvent(
        event_id="event-1",
        source="System",
        event_type="system.service_installed",
        timestamp=observed_at,
        process_id=None,
        details={"service_name": "ExampleService"},
        source_event_id=7045,
    )

    assert store.add_events([record, record]) == 1
    result = store.recent_events()

    assert len(result) == 1
    assert result[0] == record
    assert store.get_checkpoint("System") is None
    store.set_checkpoint("System", 101)
    assert store.get_checkpoint("System") == 101


def test_event_store_migrates_v1_without_losing_existing_events(tmp_path) -> None:
    database = tmp_path / "legacy.db"
    observed_at = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                process_id INTEGER,
                details_json TEXT NOT NULL
            );
            CREATE TABLE source_checkpoints (
                source TEXT PRIMARY KEY,
                record_id INTEGER NOT NULL CHECK(record_id >= 0)
            );
            PRAGMA user_version = 1;
            """
        )
        connection.execute(
            """
            INSERT INTO events
                (event_id, source, event_type, timestamp, process_id, details_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-event",
                "System",
                "system.service_installed",
                observed_at.isoformat(),
                None,
                '{"service_name": "ExistingService"}',
            ),
        )

    store = EventStore(database)

    assert store.recent_events()[0].event_id == "legacy-event"
    assert store.recent_events()[0].source_event_id is None
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


def test_event_store_migrates_v2_to_detection_schema(tmp_path) -> None:
    database = tmp_path / "v2.db"
    observed_at = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                process_id INTEGER,
                source_event_id INTEGER,
                details_json TEXT NOT NULL
            );
            CREATE TABLE source_checkpoints (
                source TEXT PRIMARY KEY,
                record_id INTEGER NOT NULL CHECK(record_id >= 0)
            );
            PRAGMA user_version = 2;
            """
        )
        connection.execute(
            """
            INSERT INTO events
                (
                    event_id, source, event_type, timestamp, process_id,
                    source_event_id, details_json
                )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "v2-event",
                "System",
                "system.service_installed",
                observed_at.isoformat(),
                None,
                7045,
                '{"service_name": "ExistingService"}',
            ),
        )

    store = EventStore(database)

    assert store.recent_events()[0].source_event_id == 7045
    assert store.recent_detections() == []
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


def test_event_store_atomically_persists_idempotent_detections(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    record = detected_event(
        "service-1",
        datetime(2026, 11, 17, 12, 0, tzinfo=UTC),
    )
    detection = DetectionEngine().evaluate([record])[0]

    assert store.persist_cycle([record], [detection, detection]) == (1, 1)
    assert store.recent_detections() == [detection]
    assert store.events_since(
        datetime(2026, 11, 17, 11, 59, tzinfo=UTC)
    ) == [record]


def test_events_since_returns_latest_window_in_chronological_order(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    start = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    records = [
        event(f"event-{index}", start + timedelta(minutes=index))
        for index in range(4)
    ]
    store.add_events(records)

    result = store.events_since(start, limit=2)

    assert [record.event_id for record in result] == ["event-2", "event-3"]


def test_event_store_rolls_back_detections_when_checkpoint_is_invalid(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    record = detected_event(
        "service-1",
        datetime(2026, 11, 17, 12, 0, tzinfo=UTC),
    )
    detection = DetectionEngine().evaluate([record])[0]

    with pytest.raises(ValueError, match="non-negative"):
        store.persist_cycle([record], [detection], {"System": -1})

    assert store.recent_events() == []
    assert store.recent_detections() == []


def test_event_store_prunes_old_detections(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db", retention_days=2)
    record = detected_event(
        "service-old",
        datetime(2026, 11, 14, 12, 0, tzinfo=UTC),
    )
    detection = DetectionEngine().evaluate([record])[0]
    store.persist_cycle([record], [detection])

    assert store.prune_detections(datetime(2026, 11, 17, 12, 0, tzinfo=UTC)) == 1
    assert store.recent_detections() == []


def test_event_store_enforces_age_and_row_count_retention(tmp_path) -> None:
    now = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    store = EventStore(
        tmp_path / "events.db",
        retention_days=2,
        max_events=2,
    )
    store.add_events(
        [
            event("expired", now - timedelta(days=3)),
            event("older", now - timedelta(hours=2)),
            event("middle", now - timedelta(hours=1)),
            event("newest", now),
        ]
    )

    assert store.prune(now) == 2
    assert {item.event_id for item in store.recent_events()} == {"middle", "newest"}


def test_event_store_rolls_back_events_when_checkpoint_is_invalid(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    record = event("event-1", datetime(2026, 11, 17, 12, 0, tzinfo=UTC))

    with pytest.raises(ValueError, match="non-negative"):
        store.persist_batch([record], {"System": -1})

    assert store.recent_events() == []
    assert store.get_checkpoint("System") is None


def test_security_event_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        event("event-1", datetime(2026, 11, 17, 12, 0))
