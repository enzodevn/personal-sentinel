"""Typed contracts for versioned rules and explainable detections."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Mapping, Protocol

from sentinel.models import SecurityEvent


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_SCORES = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 25,
    Severity.MODERATE: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 100,
}


class RiskLevel(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    rule_id: str
    version: str
    name: str
    description: str
    category: str
    criteria: str
    sources: frozenset[str]
    event_types: frozenset[str]
    evidence_fields: tuple[str, ...]
    severity: Severity
    confidence: int
    impact: int
    context: int
    mitre_techniques: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        required_text = (
            self.rule_id,
            self.version,
            self.name,
            self.description,
            self.category,
            self.criteria,
        )
        if any(not value.strip() for value in required_text):
            raise ValueError("rule metadata fields must not be empty")
        if not self.sources or not self.event_types:
            raise ValueError("rules must declare at least one source and event type")
        if not self.evidence_fields:
            raise ValueError("rules must declare expected evidence fields")
        for name, value in (
            ("confidence", self.confidence),
            ("impact", self.impact),
            ("context", self.context),
        ):
            if isinstance(value, bool) or not 0 <= value <= 100:
                raise ValueError(f"{name} must be between 0 and 100")

    @property
    def definition(self) -> RuleDefinition:
        return self

    def matches(self, event: SecurityEvent) -> bool:
        return event.source in self.sources and event.event_type in self.event_types

    def evidence_fields_for(self, event: SecurityEvent) -> tuple[str, ...]:
        return self.evidence_fields


class RuleEvaluator(Protocol):
    definition: RuleDefinition

    def matches(self, event: SecurityEvent) -> bool: ...

    def evidence_fields_for(self, event: SecurityEvent) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class DetectionEvidence:
    event_id: str
    source: str
    event_type: str
    observed_at: datetime
    process_id: int | None
    source_event_id: int | None
    details: Mapping[str, str | int | float | bool | None]


@dataclass(frozen=True, slots=True)
class Detection:
    detection_id: str
    rule_id: str
    rule_version: str
    name: str
    description: str
    category: str
    criteria: str
    severity: Severity
    confidence: int
    impact: int
    evidence_quality: int
    context: int
    risk_score: int
    risk_level: RiskLevel
    evidence: tuple[DetectionEvidence, ...]
    mitre_techniques: tuple[str, ...]
    recommendations: tuple[str, ...]
