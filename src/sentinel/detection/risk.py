"""Configurable, explainable risk scoring; scores are not infection probabilities."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.detection.models import RiskLevel


@dataclass(frozen=True, slots=True)
class RiskWeights:
    severity: int = 30
    confidence: int = 25
    impact: int = 20
    evidence_quality: int = 15
    context: int = 10

    def __post_init__(self) -> None:
        values = (
            self.severity,
            self.confidence,
            self.impact,
            self.evidence_quality,
            self.context,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in values
        ):
            raise ValueError("risk weights must be non-negative integers")
        if sum(values) != 100:
            raise ValueError("risk weights must sum to 100")


@dataclass(frozen=True, slots=True)
class RiskBands:
    informational_max: int = 19
    low_max: int = 39
    moderate_max: int = 59
    high_max: int = 79

    def __post_init__(self) -> None:
        values = (
            self.informational_max,
            self.low_max,
            self.moderate_max,
            self.high_max,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in values
        ):
            raise ValueError("risk band limits must be integers")
        if not 0 <= self.informational_max < self.low_max < self.moderate_max:
            raise ValueError("risk band limits must be increasing from zero")
        if not self.moderate_max < self.high_max < 100:
            raise ValueError("the high risk limit must be below 100")


@dataclass(frozen=True, slots=True)
class RiskComponents:
    severity: int
    confidence: int
    impact: int
    evidence_quality: int
    context: int

    def __post_init__(self) -> None:
        values = (
            self.severity,
            self.confidence,
            self.impact,
            self.evidence_quality,
            self.context,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 100
            for value in values
        ):
            raise ValueError("risk components must be integers between 0 and 100")


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    level: RiskLevel


class RiskAssessmentEngine:
    """Calculate a weighted prioritization score and its configurable band."""

    def __init__(
        self,
        *,
        weights: RiskWeights = RiskWeights(),
        bands: RiskBands = RiskBands(),
    ) -> None:
        self.weights = weights
        self.bands = bands

    def assess(self, components: RiskComponents) -> RiskAssessment:
        weighted_score = (
            components.severity * self.weights.severity
            + components.confidence * self.weights.confidence
            + components.impact * self.weights.impact
            + components.evidence_quality * self.weights.evidence_quality
            + components.context * self.weights.context
        ) / 100
        score = min(100, int(weighted_score + 0.5))
        return RiskAssessment(score=score, level=self._level(score))

    def _level(self, score: int) -> RiskLevel:
        if score <= self.bands.informational_max:
            return RiskLevel.INFORMATIONAL
        if score <= self.bands.low_max:
            return RiskLevel.LOW
        if score <= self.bands.moderate_max:
            return RiskLevel.MODERATE
        if score <= self.bands.high_max:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL
