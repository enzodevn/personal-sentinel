from datetime import UTC, datetime, timedelta

import pytest

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


def test_event_store_round_trips_and_deduplicates(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    observed_at = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    record = event("event-1", observed_at)

    assert store.add_events([record, record]) == 1
    result = store.recent_events()

    assert len(result) == 1
    assert result[0] == record
    assert store.get_checkpoint("System") is None
    store.set_checkpoint("System", 101)
    assert store.get_checkpoint("System") == 101


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
