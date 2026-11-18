from dataclasses import replace
from datetime import UTC, datetime

import pytest

from sentinel.detection.correlation import CorrelationEngine
from sentinel.detection.engine import DetectionEngine
from sentinel.detection.models import RiskLevel, Severity
from sentinel.detection.risk import (
    RiskAssessmentEngine,
    RiskBands,
    RiskComponents,
    RiskWeights,
)
from sentinel.detection.sigma import (
    MAX_SIGMA_FILE_BYTES,
    SigmaRuleError,
    SigmaRuleLoader,
)
from sentinel.models import SecurityEvent


SIGMA_PROCESS_RULE = r"""
title: Command interpreter with unusual parent
id: 11111111-2222-4333-8444-555555555555
status: test
description: Detect a process creation matching the local test selector.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    Image|endswith: '\cmd.exe'
  filter:
    ParentImage|endswith: '\explorer.exe'
  condition: selection and not filter
level: high
tags:
  - attack.execution
  - attack.t1059.003
date: 2026-11-18
falsepositives:
  - Expected command interpreter use during software installation.
"""


def event(
    *,
    source: str = "Microsoft-Windows-Sysmon/Operational",
    event_type: str = "system.autostart_registry_changed",
    details: dict[str, str | int | None] | None = None,
    event_id: str = "sysmon:13:100",
    source_event_id: int | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        source=source,
        event_type=event_type,
        timestamp=datetime(2026, 11, 18, 12, 0, tzinfo=UTC),
        process_id=1234,
        details=details or {},
        source_event_id=source_event_id,
    )


def test_risk_assessment_uses_approved_weights_and_rounds_half_up() -> None:
    engine = RiskAssessmentEngine()

    result = engine.assess(
        RiskComponents(
            severity=50,
            confidence=80,
            impact=40,
            evidence_quality=100,
            context=25,
        )
    )

    assert result.score == 61
    assert result.level is RiskLevel.HIGH


def test_risk_bands_are_configurable() -> None:
    engine = RiskAssessmentEngine(
        bands=RiskBands(
            informational_max=9,
            low_max=29,
            moderate_max=49,
            high_max=69,
        )
    )

    result = engine.assess(
        RiskComponents(
            severity=0,
            confidence=0,
            impact=0,
            evidence_quality=0,
            context=100,
        )
    )

    assert result.score == 10
    assert result.level is RiskLevel.LOW


def test_risk_configuration_rejects_invalid_values() -> None:
    with pytest.raises(ValueError, match="sum to 100"):
        RiskWeights(severity=31)
    with pytest.raises(ValueError, match="integers"):
        RiskWeights(severity=30.5)
    with pytest.raises(ValueError, match="increasing"):
        RiskBands(low_max=10)
    with pytest.raises(ValueError, match="integers"):
        RiskBands(informational_max=10.5)
    with pytest.raises(ValueError, match="between 0 and 100"):
        RiskComponents(101, 0, 0, 0, 0)
    with pytest.raises(ValueError, match="between 0 and 100"):
        RiskComponents(1.5, 0, 0, 0, 0)


def test_detection_engine_emits_explainable_autostart_detection() -> None:
    observed = event(
        details={
            "registry_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Demo",
            "operation": "SetValue",
            "unapproved_payload": "must not be copied",
        }
    )

    detections = DetectionEngine().evaluate([observed])

    assert len(detections) == 1
    detection = detections[0]
    assert detection.rule_id == "PS-WIN-AUTOSTART-001"
    assert detection.rule_version == "1.0.0"
    assert detection.severity is Severity.LOW
    assert detection.risk_score == 48
    assert detection.risk_level is RiskLevel.MODERATE
    assert detection.evidence[0].event_id == observed.event_id
    assert detection.evidence[0].details == {
        "registry_path": observed.details["registry_path"],
        "operation": "SetValue",
    }
    assert detection.mitre_techniques == ("T1547.001",)
    assert detection.recommendations


def test_detection_engine_matches_service_events_and_requires_source() -> None:
    service_event = event(
        source="System",
        event_type="system.service_installed",
        details={"service_name": "ExampleService", "start_type": "auto start"},
        event_id="System:7045:100",
    )
    unrelated_source = event(
        source="Microsoft-Windows-Sysmon/Operational",
        event_type="system.service_installed",
        details={"service_name": "ExampleService", "start_type": "auto start"},
        event_id="sysmon:1:101",
    )

    results = DetectionEngine().evaluate([service_event, unrelated_source])

    assert [item.rule_id for item in results] == ["PS-WIN-SERVICE-001"]
    assert results[0].evidence[0].source == "System"
    assert results[0].mitre_techniques == ("T1543.003",)


def test_detection_evidence_quality_and_id_are_deterministic() -> None:
    incomplete = event(
        details={"registry_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"},
    )
    engine = DetectionEngine()

    first = engine.evaluate([incomplete, incomplete])
    repeated = engine.evaluate([incomplete])

    assert len(first) == 1
    assert first[0].evidence_quality == 50
    assert first[0].risk_score < DetectionEngine().evaluate(
        [
            event(
                details={
                    "registry_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "operation": "SetValue",
                }
            )
        ]
    )[0].risk_score
    assert first[0].detection_id == repeated[0].detection_id


def test_sigma_rule_is_validated_mapped_and_evaluated() -> None:
    rules = SigmaRuleLoader().load_yaml(SIGMA_PROCESS_RULE)
    observed = event(
        event_type="process.created",
        source_event_id=1,
        event_id="sysmon:1:101",
        details={
            "image": r"C:\Windows\System32\cmd.exe",
            "parent_image": r"C:\Windows\System32\services.exe",
        },
    )

    detections = DetectionEngine(rules=rules).evaluate([observed])

    assert len(detections) == 1
    detection = detections[0]
    assert detection.rule_id == "11111111-2222-4333-8444-555555555555"
    assert detection.rule_version == "2026-11-18"
    assert detection.severity is Severity.HIGH
    assert detection.evidence[0].source_event_id == 1
    assert detection.mitre_techniques == ("T1059.003",)
    assert any("Expected command interpreter use" in item for item in detection.recommendations)


def test_sigma_rule_condition_excludes_filter_match() -> None:
    rules = SigmaRuleLoader().load_yaml(SIGMA_PROCESS_RULE)
    expected_parent = event(
        event_type="process.created",
        source_event_id=1,
        event_id="sysmon:1:102",
        details={
            "image": r"C:\Windows\System32\cmd.exe",
            "parent_image": r"C:\Windows\explorer.exe",
        },
    )

    assert DetectionEngine(rules=rules).evaluate([expected_parent]) == []


def test_sigma_rule_uses_security_channel_process_mapping() -> None:
    text = r"""
title: Security process creation
id: 22222222-3333-4444-8555-666666666666
status: test
description: Match a Security process creation record.
logsource:
  product: windows
  service: security
  category: process_creation
detection:
  selection:
    EventID: 4688
    NewProcessName|endswith: '\sample.exe'
  condition: selection
level: medium
date: 2026-11-18
"""
    rules = SigmaRuleLoader().load_yaml(text)
    observed = event(
        source="Security",
        event_type="process.created",
        source_event_id=4688,
        event_id="Security:4688:200",
        details={"image": r"C:\Apps\sample.exe", "parent_pid": 1000},
    )

    detections = DetectionEngine(rules=rules).evaluate([observed])

    assert len(detections) == 1
    assert detections[0].risk_level is RiskLevel.MODERATE


def test_sigma_loader_rejects_fields_not_collected_for_privacy() -> None:
    text = SIGMA_PROCESS_RULE.replace(
        "Image|endswith: '\\cmd.exe'",
        "CommandLine|contains: secret",
    )

    with pytest.raises(SigmaRuleError, match="CommandLine"):
        SigmaRuleLoader().load_yaml(text)


def test_sigma_loader_rejects_unsupported_condition_and_event_id() -> None:
    unsupported_condition = SIGMA_PROCESS_RULE.replace(
        "selection and not filter",
        "1 of selection*",
    )
    with pytest.raises(SigmaRuleError, match="condition"):
        SigmaRuleLoader().load_yaml(unsupported_condition)

    unsupported_event_id = SIGMA_PROCESS_RULE.replace(
        "EventID: 1",
        "EventID: 7045",
    )
    with pytest.raises(SigmaRuleError, match="EventID"):
        SigmaRuleLoader().load_yaml(unsupported_event_id)


def test_sigma_loader_reads_local_rule_file(tmp_path) -> None:
    rule_path = tmp_path / "process.yml"
    rule_path.write_text(SIGMA_PROCESS_RULE, encoding="utf-8")

    rules = SigmaRuleLoader().load(rule_path)

    assert len(rules) == 1
    assert rules[0].definition.sources == frozenset(
        {"Microsoft-Windows-Sysmon/Operational"}
    )


def test_sigma_loader_rejects_oversized_file_before_parsing(tmp_path) -> None:
    rule_file = tmp_path / "oversized.yml"
    rule_file.write_bytes(b"x" * (MAX_SIGMA_FILE_BYTES + 1))

    with pytest.raises(SigmaRuleError, match="exceeds"):
        SigmaRuleLoader().load(rule_file)


def test_correlation_requires_same_process_and_window_and_keeps_both_evidence() -> None:
    process_start = event(
        event_type="process.created",
        source_event_id=1,
        event_id="sysmon:1:301",
        details={"image": r"C:\Apps\installer.exe"},
    )
    registry_change = event(
        event_id="sysmon:13:302",
        source_event_id=13,
        details={
            "registry_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Demo",
            "operation": "SetValue",
        },
    )
    engine = CorrelationEngine()

    detections = engine.evaluate([process_start, registry_change])

    assert len(detections) == 1
    detection = detections[0]
    assert detection.rule_id == "PS-CORR-AUTOSTART-001"
    assert detection.risk_score == 56
    assert detection.risk_level is RiskLevel.MODERATE
    assert {item.event_id for item in detection.evidence} == {
        process_start.event_id,
        registry_change.event_id,
    }
    assert engine.evaluate([process_start, registry_change, registry_change]) == [
        detection
    ]

    other_process = replace(registry_change, process_id=4321)
    missing_pid = replace(registry_change, process_id=None)
    wrong_source = replace(registry_change, source="System")
    boundary_change = replace(
        registry_change,
        timestamp=datetime(2026, 11, 18, 12, 5, tzinfo=UTC),
    )
    late_change = replace(
        registry_change,
        timestamp=datetime(2026, 11, 18, 12, 5, 1, tzinfo=UTC),
    )
    assert engine.evaluate([process_start, other_process]) == []
    assert engine.evaluate([process_start, missing_pid]) == []
    assert engine.evaluate([process_start, wrong_source]) == []
    assert len(engine.evaluate([process_start, boundary_change])) == 1
    assert engine.evaluate([process_start, late_change]) == []
