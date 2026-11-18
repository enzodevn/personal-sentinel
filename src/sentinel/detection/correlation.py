"""Bounded correlation of related, read-only telemetry events."""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_left
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from sentinel.detection.models import (
    Detection,
    DetectionEvidence,
    RuleDefinition,
    SEVERITY_SCORES,
    Severity,
)
from sentinel.detection.risk import RiskAssessmentEngine, RiskComponents
from sentinel.models import SecurityEvent


_PROCESS_CREATED = "process.created"
_AUTOSTART_CHANGED = "system.autostart_registry_changed"
_SYSMON_SOURCE = "Microsoft-Windows-Sysmon/Operational"


@dataclass(frozen=True, slots=True)
class CorrelationRule:
    definition: RuleDefinition
    first_event_type: str
    second_event_type: str
    window_seconds: int
    evidence_fields_by_type: Mapping[str, tuple[str, ...]]

    def __post_init__(self) -> None:
        if self.first_event_type == self.second_event_type:
            raise ValueError("correlation event types must be distinct")
        if {self.first_event_type, self.second_event_type} != set(
            self.definition.event_types
        ):
            raise ValueError("correlation event types must match rule metadata")
        if (
            isinstance(self.window_seconds, bool)
            or not isinstance(self.window_seconds, int)
            or self.window_seconds <= 0
        ):
            raise ValueError("correlation window must be greater than zero")
        if set(self.evidence_fields_by_type) != {
            self.first_event_type,
            self.second_event_type,
        }:
            raise ValueError("evidence fields must be declared for both event types")
        if any(not fields for fields in self.evidence_fields_by_type.values()):
            raise ValueError("each correlated event type needs evidence fields")


DEFAULT_CORRELATION_RULES = (
    CorrelationRule(
        definition=RuleDefinition(
            rule_id="PS-CORR-AUTOSTART-001",
            version="1.0.0",
            name="Process creation near autostart registry change",
            description=(
                "The same process ID was observed at process creation and during "
                "a monitored autostart registry change. Legitimate installers can "
                "produce this pattern."
            ),
            category="persistence",
            criteria=(
                "A Sysmon process creation and monitored autostart registry change "
                "share a process ID and occur within five minutes."
            ),
            sources=frozenset({_SYSMON_SOURCE}),
            event_types=frozenset({_PROCESS_CREATED, _AUTOSTART_CHANGED}),
            evidence_fields=(
                "process_id",
                "image",
                "registry_path",
                "operation",
            ),
            severity=Severity.LOW,
            confidence=70,
            impact=50,
            context=60,
            mitre_techniques=("T1547.001",),
            recommendations=(
                "Confirm whether the process and startup change belong to an authorized installation.",
                "Review the process image and registry path using trusted system tools.",
            ),
        ),
        first_event_type=_PROCESS_CREATED,
        second_event_type=_AUTOSTART_CHANGED,
        window_seconds=300,
        evidence_fields_by_type={
            _PROCESS_CREATED: ("process_id", "image"),
            _AUTOSTART_CHANGED: ("process_id", "registry_path", "operation"),
        },
    ),
)


class CorrelationEngine:
    """Create one idempotent finding per matching process and correlation rule."""

    def __init__(
        self,
        rules: Iterable[CorrelationRule] = DEFAULT_CORRELATION_RULES,
        risk_assessment: RiskAssessmentEngine | None = None,
    ) -> None:
        self.rules = tuple(rules)
        rule_ids = [rule.definition.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("correlation rule IDs must be unique")
        self.risk_assessment = risk_assessment or RiskAssessmentEngine()

    @property
    def max_window_seconds(self) -> int:
        return max((rule.window_seconds for rule in self.rules), default=0)

    def evaluate(self, events: Iterable[SecurityEvent]) -> list[Detection]:
        observed = tuple(events)
        detections: dict[str, Detection] = {}
        for rule in self.rules:
            grouped: dict[int, dict[str, list[SecurityEvent]]] = defaultdict(
                lambda: defaultdict(list)
            )
            for event in observed:
                if (
                    event.source in rule.definition.sources
                    and event.event_type in rule.definition.event_types
                    and event.process_id is not None
                ):
                    grouped[event.process_id][event.event_type].append(event)
            for process_events in grouped.values():
                pair = self._best_pair(rule, process_events)
                if pair is None:
                    continue
                detection = self._build_detection(rule, pair)
                detections[detection.detection_id] = detection
        return list(detections.values())

    @staticmethod
    def _best_pair(
        rule: CorrelationRule,
        process_events: Mapping[str, list[SecurityEvent]],
    ) -> tuple[SecurityEvent, SecurityEvent] | None:
        first_events = sorted(
            process_events.get(rule.first_event_type, ()),
            key=lambda event: (event.timestamp, event.event_id),
        )
        second_events = sorted(
            process_events.get(rule.second_event_type, ()),
            key=lambda event: (event.timestamp, event.event_id),
        )
        second_times = [event.timestamp for event in second_events]
        candidates: list[tuple[float, str, str, SecurityEvent, SecurityEvent]] = []
        for first in first_events:
            index = bisect_left(second_times, first.timestamp)
            for candidate_index in (index - 1, index):
                if 0 <= candidate_index < len(second_events):
                    second = second_events[candidate_index]
                    delta = abs((first.timestamp - second.timestamp).total_seconds())
                    if delta <= rule.window_seconds:
                        candidates.append(
                            (
                                delta,
                                min(first.event_id, second.event_id),
                                max(first.event_id, second.event_id),
                                first,
                                second,
                            )
                        )
        if not candidates:
            return None
        best = min(candidates, key=lambda item: item[:3])
        return best[3], best[4]

    def _build_detection(
        self,
        rule: CorrelationRule,
        pair: tuple[SecurityEvent, SecurityEvent],
    ) -> Detection:
        definition = rule.definition
        evidence: list[DetectionEvidence] = []
        expected_count = 0
        present_count = 0
        for event in pair:
            fields = rule.evidence_fields_by_type[event.event_type]
            details = {
                field: event.details[field]
                for field in fields
                if field not in {"process_id", "source_event_id"}
                and field in event.details
                and event.details[field] not in (None, "")
            }
            expected_count += len(fields)
            present_count += sum(
                _field_value(event, field) not in (None, "") for field in fields
            )
            evidence.append(
                DetectionEvidence(
                    event_id=event.event_id,
                    source=event.source,
                    event_type=event.event_type,
                    observed_at=event.timestamp,
                    process_id=event.process_id,
                    source_event_id=event.source_event_id,
                    details=details,
                )
            )
        evidence_quality = present_count * 100 // expected_count
        risk = self.risk_assessment.assess(
            RiskComponents(
                severity=SEVERITY_SCORES[definition.severity],
                confidence=definition.confidence,
                impact=definition.impact,
                evidence_quality=evidence_quality,
                context=definition.context,
            )
        )
        identity = json.dumps(
            (
                definition.rule_id,
                definition.version,
                *sorted(event.event_id for event in pair),
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        detection_id = (
            f"{definition.rule_id}:{hashlib.sha256(identity).hexdigest()}"
        )
        return Detection(
            detection_id=detection_id,
            rule_id=definition.rule_id,
            rule_version=definition.version,
            name=definition.name,
            description=definition.description,
            category=definition.category,
            criteria=definition.criteria,
            severity=definition.severity,
            confidence=definition.confidence,
            impact=definition.impact,
            evidence_quality=evidence_quality,
            context=definition.context,
            risk_score=risk.score,
            risk_level=risk.level,
            evidence=tuple(evidence),
            mitre_techniques=definition.mitre_techniques,
            recommendations=definition.recommendations,
        )


def _field_value(event: SecurityEvent, field: str) -> object | None:
    if field == "process_id":
        return event.process_id
    if field == "source_event_id":
        return event.source_event_id
    return event.details.get(field)
