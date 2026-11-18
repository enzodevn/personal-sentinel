"""In-memory rule evaluation over normalized, locally collected events."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from sentinel.detection.models import (
    Detection,
    DetectionEvidence,
    RuleDefinition,
    RuleEvaluator,
    SEVERITY_SCORES,
    Severity,
)
from sentinel.detection.risk import (
    RiskAssessmentEngine,
    RiskComponents,
)
from sentinel.models import SecurityEvent


DEFAULT_RULES = (
    RuleDefinition(
        rule_id="PS-WIN-AUTOSTART-001",
        version="1.0.0",
        name="Autostart registry change observed",
        description=(
            "A monitored Windows autostart registry key changed. "
            "This can be legitimate software activity and is not a malware verdict."
        ),
        category="persistence",
        criteria="A selected Sysmon event identifies a monitored autostart registry key.",
        sources=frozenset({"Microsoft-Windows-Sysmon/Operational"}),
        event_types=frozenset({"system.autostart_registry_changed"}),
        evidence_fields=("registry_path", "operation"),
        severity=Severity.LOW,
        confidence=75,
        impact=35,
        context=0,
        mitre_techniques=("T1547.001",),
        recommendations=(
            "Confirm whether the registry change was expected.",
            "Review the recorded process and change time using trusted system tools.",
        ),
    ),
    RuleDefinition(
        rule_id="PS-WIN-SERVICE-001",
        version="1.0.0",
        name="Service installation observed",
        description=(
            "Windows reported a service installation. Service installation can be "
            "legitimate and is not a malware verdict."
        ),
        category="persistence",
        criteria="A selected System event reports a newly installed service.",
        sources=frozenset({"System"}),
        event_types=frozenset({"system.service_installed"}),
        evidence_fields=("service_name", "start_type"),
        severity=Severity.LOW,
        confidence=75,
        impact=40,
        context=0,
        mitre_techniques=("T1543.003",),
        recommendations=(
            "Confirm whether the service installation was authorized.",
            "Review the service details in Windows; Sentinel does not retain its executable path.",
        ),
    ),
    RuleDefinition(
        rule_id="PS-WIN-SERVICE-002",
        version="1.0.0",
        name="Service start type change observed",
        description=(
            "Windows reported a service start-type change. This can be an expected "
            "administrative or software update."
        ),
        category="persistence",
        criteria="A selected System event reports a service start-type change.",
        sources=frozenset({"System"}),
        event_types=frozenset({"system.service_start_type_changed"}),
        evidence_fields=("service_name",),
        severity=Severity.INFORMATIONAL,
        confidence=75,
        impact=25,
        context=0,
        mitre_techniques=("T1543.003",),
        recommendations=("Confirm whether the service configuration change was expected.",),
    ),
)


class DetectionEngine:
    """Evaluate versioned rules without changing telemetry or host state."""

    def __init__(
        self,
        rules: Iterable[RuleEvaluator] = DEFAULT_RULES,
        risk_assessment: RiskAssessmentEngine | None = None,
    ) -> None:
        self.rules = tuple(rules)
        rule_ids = [rule.definition.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rule IDs must be unique")
        self.risk_assessment = risk_assessment or RiskAssessmentEngine()

    def evaluate(self, events: Iterable[SecurityEvent]) -> list[Detection]:
        detections: dict[str, Detection] = {}
        for event in events:
            for rule in self.rules:
                if not rule.matches(event):
                    continue
                detection = self._evaluate_rule(rule, event)
                detections[detection.detection_id] = detection
        return list(detections.values())

    def _evaluate_rule(
        self,
        rule: RuleEvaluator,
        event: SecurityEvent,
    ) -> Detection:
        definition = rule.definition
        expected_fields = rule.evidence_fields_for(event)
        evidence_details = {
            field: event.details[field]
            for field in expected_fields
            if field in event.details and event.details[field] not in (None, "")
        }
        present_fields = sum(
            self._field_value(event, field) not in (None, "")
            for field in expected_fields
        )
        evidence_quality = present_fields * 100 // len(expected_fields)
        risk = self.risk_assessment.assess(
            RiskComponents(
                severity=SEVERITY_SCORES[definition.severity],
                confidence=definition.confidence,
                impact=definition.impact,
                evidence_quality=evidence_quality,
                context=definition.context,
            )
        )
        evidence = DetectionEvidence(
            event_id=event.event_id,
            source=event.source,
            event_type=event.event_type,
            observed_at=event.timestamp,
            process_id=event.process_id,
            source_event_id=event.source_event_id,
            details=evidence_details,
        )
        detection_id = self._detection_id(definition, event.event_id)
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
            evidence=(evidence,),
            mitre_techniques=definition.mitre_techniques,
            recommendations=definition.recommendations,
        )

    @staticmethod
    def _field_value(event: SecurityEvent, field: str) -> object | None:
        if field == "source_event_id":
            return event.source_event_id
        if field == "process_id":
            return event.process_id
        return event.details.get(field)

    @staticmethod
    def _detection_id(rule: RuleDefinition, event_id: str) -> str:
        identity = json.dumps(
            (rule.rule_id, rule.version, event_id),
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(identity).hexdigest()
        return f"{rule.rule_id}:{digest}"
