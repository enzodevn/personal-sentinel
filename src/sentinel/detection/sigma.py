"""Validated, local-only evaluation of a documented Sigma rule subset."""

from __future__ import annotations

import ast
import fnmatch
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import TypeAlias

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from sentinel.detection.models import (
    RuleDefinition,
    Severity,
    SEVERITY_SCORES,
)
from sentinel.detection.models import RuleEvaluator
from sentinel.models import SecurityEvent


MAX_SIGMA_FILE_BYTES = 256_000
MAX_SIGMA_RULES = 128

_SIGMA_LEVELS = {
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MODERATE,
    "moderate": Severity.MODERATE,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_FIELD_DETAILS = {
    "eventrecordid": "record_id",
    "image": "image",
    "newprocessname": "image",
    "processname": "image",
    "parentimage": "parent_image",
    "parentprocessid": "parent_pid",
    "protocol": "protocol",
    "sourceip": "source_ip",
    "sourceport": "source_port",
    "destinationip": "destination_ip",
    "destinationhostname": "destination_hostname",
    "destinationport": "destination_port",
    "targetobject": "registry_path",
    "eventtype": "operation",
    "servicename": "service_name",
    "starttype": "start_type",
    "provider": "provider",
}


class SigmaRuleError(ValueError):
    """A Sigma rule is invalid or requires telemetry Sentinel does not support."""


@dataclass(frozen=True, slots=True)
class _EventShape:
    source: str
    event_id: int
    event_type: str
    fields: frozenset[str]


_EVENT_SHAPES = (
    _EventShape(
        "Microsoft-Windows-Sysmon/Operational",
        1,
        "process.created",
        frozenset(
            {
                "eventid",
                "eventrecordid",
                "processid",
                "image",
                "parentimage",
                "parentprocessid",
            }
        ),
    ),
    _EventShape(
        "Microsoft-Windows-Sysmon/Operational",
        3,
        "network.connection_observed",
        frozenset(
            {
                "eventid",
                "eventrecordid",
                "processid",
                "image",
                "protocol",
                "sourceip",
                "sourceport",
                "destinationip",
                "destinationhostname",
                "destinationport",
            }
        ),
    ),
    *(
        _EventShape(
            "Microsoft-Windows-Sysmon/Operational",
            event_id,
            event_type,
            frozenset(
                {
                    "eventid",
                    "eventrecordid",
                    "processid",
                    "image",
                    "targetobject",
                    "eventtype",
                }
            ),
        )
        for event_id in (12, 13, 14)
        for event_type in (
            "system.autostart_registry_changed",
            "system.service_registry_changed",
        )
    ),
    _EventShape(
        "Security",
        4688,
        "process.created",
        frozenset(
            {
                "eventid",
                "eventrecordid",
                "processid",
                "image",
                "newprocessid",
                "newprocessname",
            }
        ),
    ),
    _EventShape(
        "Security",
        4689,
        "process.exited",
        frozenset({"eventid", "eventrecordid", "processid", "processname"}),
    ),
    *(
        _EventShape(
            "System",
            event_id,
            event_type,
            frozenset({"eventid", "eventrecordid", "provider"}),
        )
        for event_id, event_type in (
            (6005, "windows.event_log_service_started"),
            (6006, "windows.event_log_service_stopped"),
            (6008, "windows.unexpected_shutdown"),
        )
    ),
    _EventShape(
        "System",
        7040,
        "system.service_start_type_changed",
        frozenset({"eventid", "eventrecordid", "servicename"}),
    ),
    _EventShape(
        "System",
        7045,
        "system.service_installed",
        frozenset({"eventid", "eventrecordid", "provider", "servicename", "starttype"}),
    ),
)

_CATEGORY_EVENT_IDS = {
    "process_creation": frozenset({1, 4688}),
    "network_connection": frozenset({3}),
    "registry_event": frozenset({12, 13, 14}),
}
_SERVICE_SOURCES = {
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "security": "Security",
    "system": "System",
}
MAX_SIGMA_TOTAL_BYTES = 2_000_000

_Scalar: TypeAlias = str | int | float | bool


@dataclass(frozen=True, slots=True)
class _FieldMatch:
    sigma_field: str
    normalized_field: str
    modifier: str
    values: tuple[_Scalar, ...]
    match_all: bool

    def matches(self, event: SecurityEvent) -> bool:
        actual = _event_value(event, self.sigma_field)
        if actual is None:
            return False
        results = tuple(_value_matches(actual, value, self.modifier) for value in self.values)
        return all(results) if self.match_all else any(results)

    def evidence_field(self, event: SecurityEvent) -> str:
        if self.normalized_field == "process_id":
            if event.source == "Security" and event.source_event_id == 4688:
                return "parent_pid"
            return "process_id"
        return self.normalized_field


@dataclass(frozen=True, slots=True)
class _Selector:
    alternatives: tuple[tuple[_FieldMatch, ...], ...]

    def matches(self, event: SecurityEvent) -> bool:
        return any(
            all(field_match.matches(event) for field_match in alternative)
            for alternative in self.alternatives
        )


@dataclass(frozen=True, slots=True)
class SigmaCompiledRule:
    definition: RuleDefinition
    selectors: Mapping[str, _Selector]
    condition: ast.expr
    event_ids_by_source: Mapping[str, frozenset[int]]

    def matches(self, event: SecurityEvent) -> bool:
        if (
            event.source not in self.definition.sources
            or event.event_type not in self.definition.event_types
            or event.source_event_id
            not in self.event_ids_by_source.get(event.source, frozenset())
        ):
            return False
        return _evaluate_condition(self.condition, self.selectors, event)

    def evidence_fields_for(self, event: SecurityEvent) -> tuple[str, ...]:
        fields = dict.fromkeys(
            field_match.evidence_field(event)
            for selector in self.selectors.values()
            for alternative in selector.alternatives
            for field_match in alternative
        )
        if "source_event_id" not in fields:
            fields["source_event_id"] = None
        return tuple(fields)


class SigmaRuleLoader:
    """Load local Sigma YAML after validation and compile supported event rules."""

    def load(self, path: str | Path) -> tuple[SigmaCompiledRule, ...]:
        root = Path(path)
        if root.is_file():
            files = [root]
        elif root.is_dir():
            files = []
            for item in root.rglob("*"):
                if item.is_file() and item.suffix.casefold() in {".yml", ".yaml"}:
                    files.append(item)
                    if len(files) > MAX_SIGMA_RULES:
                        raise SigmaRuleError(
                            f"At most {MAX_SIGMA_RULES} Sigma rule files are supported."
                        )
            files.sort()
        else:
            raise FileNotFoundError(f"Sigma rule path does not exist: {root}")
        if not files:
            raise SigmaRuleError(f"No .yml or .yaml Sigma rules found at {root}.")
        if len(files) > MAX_SIGMA_RULES:
            raise SigmaRuleError(f"At most {MAX_SIGMA_RULES} Sigma rule files are supported.")

        rules: list[SigmaCompiledRule] = []
        total_bytes = 0
        for file in files:
            remaining_bytes = MAX_SIGMA_TOTAL_BYTES - total_bytes
            read_limit = min(MAX_SIGMA_FILE_BYTES, remaining_bytes) + 1
            with file.open("rb") as rule_file:
                content = rule_file.read(read_limit)
            if len(content) > MAX_SIGMA_FILE_BYTES:
                raise SigmaRuleError(
                    f"Sigma rule file exceeds {MAX_SIGMA_FILE_BYTES} bytes: {file}"
                )
            total_bytes += len(content)
            if total_bytes > MAX_SIGMA_TOTAL_BYTES:
                raise SigmaRuleError(
                    f"Sigma rules exceed the {MAX_SIGMA_TOTAL_BYTES}-byte total limit."
                )
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as error:
                raise SigmaRuleError(f"Sigma rule file is not UTF-8: {file}") from error
            rules.extend(self.load_yaml(text, source=str(file)))
            if len(rules) > MAX_SIGMA_RULES:
                raise SigmaRuleError(
                    f"At most {MAX_SIGMA_RULES} Sigma rules are supported."
                )
        ids = [rule.definition.rule_id for rule in rules]
        if len(ids) != len(set(ids)):
            raise SigmaRuleError("Sigma rule IDs must be unique.")
        return tuple(rules)

    def load_yaml(
        self,
        text: str,
        *,
        source: str = "<memory>",
    ) -> tuple[SigmaCompiledRule, ...]:
        if len(text.encode("utf-8")) > MAX_SIGMA_FILE_BYTES:
            raise SigmaRuleError(
                f"Sigma rule input exceeds {MAX_SIGMA_FILE_BYTES} bytes: {source}"
            )
        try:
            collection = SigmaCollection.from_yaml(text)
            documents = [document for document in yaml.safe_load_all(text) if document]
        except (SigmaError, yaml.YAMLError) as error:
            raise SigmaRuleError(f"Invalid Sigma YAML in {source}: {error}") from error
        if not collection.rules or len(collection.rules) != len(documents):
            raise SigmaRuleError(
                f"Expected standard Sigma detection rules only in {source}; "
                "empty documents and Sigma correlation rules are not supported."
            )

        compiled: list[SigmaCompiledRule] = []
        for parsed_rule, document in zip(collection.rules, documents):
            if not isinstance(parsed_rule, SigmaRule):
                raise SigmaRuleError(
                    f"Sigma correlation and non-detection rule types are not supported: {source}"
                )
            if not isinstance(document, dict):
                raise SigmaRuleError(f"Each Sigma document must be a mapping: {source}")
            compiled.append(self._compile_rule(parsed_rule, document, source))
        ids = [rule.definition.rule_id for rule in compiled]
        if len(ids) != len(set(ids)):
            raise SigmaRuleError(f"Sigma rule IDs must be unique within {source}.")
        return tuple(compiled)

    def _compile_rule(
        self,
        parsed_rule: SigmaRule,
        document: dict[object, object],
        source: str,
    ) -> SigmaCompiledRule:
        title = document.get("title")
        level_text = document.get("level")
        if not isinstance(title, str) or not title.strip():
            raise SigmaRuleError(f"Sigma rule title is required: {source}")
        if parsed_rule.id is None:
            raise SigmaRuleError(f"Sigma rule UUID is required: {title}")
        if not isinstance(level_text, str) or level_text.casefold() not in _SIGMA_LEVELS:
            raise SigmaRuleError(
                f"Sigma rule must declare a supported level: {title}"
            )
        version_value = document.get("modified") or document.get("date")
        if not isinstance(version_value, (date, datetime, str)):
            raise SigmaRuleError(
                f"Sigma rule must declare a date or modified version: {title}"
            )
        version = (
            version_value.isoformat()
            if isinstance(version_value, (date, datetime))
            else version_value.strip()
        )
        if not version:
            raise SigmaRuleError(f"Sigma rule version must not be empty: {title}")

        logsource = document.get("logsource")
        detection = document.get("detection")
        if not isinstance(logsource, dict) or not isinstance(detection, dict):
            raise SigmaRuleError(
                f"Sigma rule needs logsource and detection mappings: {title}"
            )
        condition_text = detection.get("condition")
        if not isinstance(condition_text, str) or not condition_text.strip():
            raise SigmaRuleError(f"Sigma rule needs one condition string: {title}")
        selectors_raw = {
            name: value for name, value in detection.items() if name != "condition"
        }
        if not selectors_raw or any(not isinstance(name, str) for name in selectors_raw):
            raise SigmaRuleError(f"Sigma rule selectors are invalid: {title}")
        selectors = {
            name: _compile_selector(name, value, title)
            for name, value in selectors_raw.items()
        }
        condition = _parse_condition(condition_text, selectors.keys(), title)
        referenced_names = _condition_names(condition)
        if referenced_names != set(selectors):
            raise SigmaRuleError(
                f"Every selector must be referenced by the condition in {title}."
            )

        field_names = {
            field_match.normalized_field
            for selector in selectors.values()
            for alternative in selector.alternatives
            for field_match in alternative
        }
        sigma_fields = {
            field_match.sigma_field.casefold()
            for selector in selectors.values()
            for alternative in selector.alternatives
            for field_match in alternative
        }
        shapes = _supported_shapes(logsource, sigma_fields, title)
        event_ids_by_source = _event_ids_by_source(shapes, selectors, title)
        sources = frozenset(event_ids_by_source)
        event_types = frozenset(shape.event_type for shape in shapes)

        tags = document.get("tags", [])
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            raise SigmaRuleError(f"Sigma rule tags must be a list of strings: {title}")
        techniques = tuple(
            sorted(
                {
                    tag.split(".", 1)[1].upper()
                    for tag in tags
                    if tag.casefold().startswith("attack.t")
                    and _is_attack_technique(tag.split(".", 1)[1])
                }
            )
        )
        false_positives = document.get("falsepositives", [])
        if not isinstance(false_positives, list) or any(
            not isinstance(item, str) for item in false_positives
        ):
            raise SigmaRuleError(
                f"Sigma rule falsepositives must be a list of strings: {title}"
            )
        recommendations = [
            "Review the matched telemetry and verify the activity; a rule match is not a verdict."
        ]
        recommendations.extend(
            f"Consider documented false-positive case: {item}"
            for item in false_positives
        )
        category = str(logsource.get("category") or logsource.get("service") or "windows")
        severity = _SIGMA_LEVELS[level_text.casefold()]
        definition = RuleDefinition(
            rule_id=str(parsed_rule.id),
            version=version,
            name=title,
            description=str(
                document.get("description")
                or "Imported Sigma detection rule; review its matched evidence."
            ),
            category=category,
            criteria=condition_text,
            sources=sources,
            event_types=event_types,
            evidence_fields=tuple(sorted(field_names)),
            severity=severity,
            confidence=75,
            impact=SEVERITY_SCORES[severity],
            context=0,
            mitre_techniques=techniques,
            recommendations=tuple(recommendations),
        )
        return SigmaCompiledRule(
            definition=definition,
            selectors=selectors,
            condition=condition,
            event_ids_by_source=event_ids_by_source,
        )


def _compile_selector(name: str, raw: object, title: str) -> _Selector:
    alternatives_raw: list[object]
    if isinstance(raw, dict):
        alternatives_raw = [raw]
    elif isinstance(raw, list) and raw and all(isinstance(item, dict) for item in raw):
        alternatives_raw = raw
    else:
        raise SigmaRuleError(
            f"Selector {name} must be a mapping or a non-empty list of mappings: {title}"
        )
    alternatives: list[tuple[_FieldMatch, ...]] = []
    for alternative in alternatives_raw:
        field_matches = tuple(
            _compile_field_match(field_name, value, title)
            for field_name, value in alternative.items()
            if isinstance(field_name, str)
        )
        if len(field_matches) != len(alternative) or not field_matches:
            raise SigmaRuleError(f"Selector {name} has an invalid field: {title}")
        alternatives.append(field_matches)
    return _Selector(tuple(alternatives))


def _compile_field_match(field_name: str, raw_value: object, title: str) -> _FieldMatch:
    parts = field_name.split("|")
    sigma_field = parts[0]
    normalized_field = _normalized_field(sigma_field, title)
    modifiers = parts[1:]
    allowed_modifiers = {"contains", "startswith", "endswith", "all"}
    if len(set(modifiers)) != len(modifiers) or not set(modifiers) <= allowed_modifiers:
        raise SigmaRuleError(
            f"Unsupported Sigma modifier in {field_name!r}: {title}"
        )
    value_modifiers = [item for item in modifiers if item != "all"]
    if len(value_modifiers) > 1:
        raise SigmaRuleError(
            f"Only one Sigma string modifier is supported per field: {title}"
        )
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    if not values or any(
        isinstance(value, (dict, list)) or not isinstance(value, (str, int, float, bool))
        for value in values
    ):
        raise SigmaRuleError(
            f"Sigma field {field_name!r} must use scalar values: {title}"
        )
    modifier = value_modifiers[0] if value_modifiers else "equals"
    if modifier != "equals" and any(not isinstance(value, str) for value in values):
        raise SigmaRuleError(
            f"String modifier {modifier!r} requires string values: {title}"
        )
    if sigma_field.casefold() == "eventid":
        if modifier != "equals" or any(
            isinstance(value, bool) or not _is_integer_value(value) for value in values
        ):
            raise SigmaRuleError(f"EventID requires integer equality values: {title}")
        values = [int(value) for value in values]
    return _FieldMatch(
        sigma_field=sigma_field,
        normalized_field=normalized_field,
        modifier=modifier,
        values=tuple(values),
        match_all="all" in modifiers,
    )


def _normalized_field(field: str, title: str) -> str:
    key = field.casefold()
    if key == "eventid":
        return "source_event_id"
    if key == "processid" or key == "newprocessid":
        return "process_id"
    try:
        return _FIELD_DETAILS[key]
    except KeyError as error:
        raise SigmaRuleError(
            f"Sigma field {field!r} is not available in Sentinel telemetry: {title}"
        ) from error


def _supported_shapes(
    logsource: Mapping[object, object],
    sigma_fields: set[str],
    title: str,
) -> tuple[_EventShape, ...]:
    product = logsource.get("product")
    category = logsource.get("category")
    service = logsource.get("service")
    if not isinstance(product, str) or product.casefold() != "windows":
        raise SigmaRuleError(f"Only Windows Sigma log sources are supported: {title}")
    if category is not None and not isinstance(category, str):
        raise SigmaRuleError(f"Unsupported Sigma logsource category: {title}")
    if service is not None and not isinstance(service, str):
        raise SigmaRuleError(f"Unsupported Sigma logsource service: {title}")

    shapes = _EVENT_SHAPES
    if category is not None:
        category_ids = _CATEGORY_EVENT_IDS.get(category.casefold())
        if category_ids is None:
            raise SigmaRuleError(
                f"Sigma category {category!r} has no Sentinel source mapping: {title}"
            )
        shapes = tuple(shape for shape in shapes if shape.event_id in category_ids)
    if service is not None:
        source = _SERVICE_SOURCES.get(service.casefold())
        if source is None:
            raise SigmaRuleError(
                f"Sigma service {service!r} has no Sentinel source mapping: {title}"
            )
        shapes = tuple(shape for shape in shapes if shape.source == source)
    if category is None and service is None:
        raise SigmaRuleError(
            f"Sigma logsource must declare a supported category or service: {title}"
        )
    shapes = tuple(
        shape for shape in shapes if sigma_fields <= shape.fields
    )
    if not shapes:
        raise SigmaRuleError(
            f"Sigma fields or logsource are not available in the configured "
            f"telemetry for rule {title}."
        )
    return shapes


def _event_ids_by_source(
    shapes: tuple[_EventShape, ...],
    selectors: Mapping[str, _Selector],
    title: str,
) -> dict[str, frozenset[int]]:
    allowed_ids = {shape.event_id for shape in shapes}
    declared_ids = {
        int(value)
        for selector in selectors.values()
        for alternative in selector.alternatives
        for field_match in alternative
        if field_match.sigma_field.casefold() == "eventid"
        for value in field_match.values
    }
    if declared_ids and not declared_ids <= allowed_ids:
        unsupported = ", ".join(str(value) for value in sorted(declared_ids - allowed_ids))
        raise SigmaRuleError(
            f"Sigma EventID value(s) {unsupported} are not collected for {title}."
        )
    return {
        source: frozenset(shape.event_id for shape in shapes if shape.source == source)
        for source in sorted({shape.source for shape in shapes})
    }


def _parse_condition(
    condition: str,
    selector_names: Iterable[str],
    title: str,
) -> ast.expr:
    try:
        expression = ast.parse(condition, mode="eval").body
    except SyntaxError as error:
        raise SigmaRuleError(
            f"Unsupported Sigma condition syntax in {title}: {condition}"
        ) from error
    names = set(selector_names)

    def validate(node: ast.AST) -> None:
        if isinstance(node, ast.Name):
            if node.id not in names:
                raise SigmaRuleError(
                    f"Sigma condition references unknown selector {node.id!r}: {title}"
                )
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            if len(node.values) < 2:
                raise SigmaRuleError(f"Invalid Sigma boolean condition: {title}")
            for child in node.values:
                validate(child)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            validate(node.operand)
        else:
            raise SigmaRuleError(
                f"Unsupported Sigma condition expression in {title}: {condition}"
            )

    validate(expression)
    return expression


def _evaluate_condition(
    expression: ast.expr,
    selectors: Mapping[str, _Selector],
    event: SecurityEvent,
) -> bool:
    if isinstance(expression, ast.Name):
        return selectors[expression.id].matches(event)
    if isinstance(expression, ast.BoolOp):
        values = (
            _evaluate_condition(child, selectors, event)
            for child in expression.values
        )
        return all(values) if isinstance(expression.op, ast.And) else any(values)
    if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
        return not _evaluate_condition(expression.operand, selectors, event)
    raise ValueError(f"Unexpected compiled Sigma condition: {type(expression).__name__}")


def _condition_names(expression: ast.expr) -> set[str]:
    return {
        node.id
        for node in ast.walk(expression)
        if isinstance(node, ast.Name)
    }


def _event_value(event: SecurityEvent, sigma_field: str) -> object | None:
    key = sigma_field.casefold()
    if key == "eventid":
        return event.source_event_id
    if key == "processid":
        if event.source == "Security" and event.source_event_id == 4688:
            return event.details.get("parent_pid")
        return event.process_id
    if key == "newprocessid":
        return event.process_id
    if key == "eventrecordid":
        return event.details.get("record_id")
    return event.details.get(_FIELD_DETAILS[key])


def _value_matches(actual: object, expected: _Scalar, modifier: str) -> bool:
    if modifier == "contains":
        return isinstance(actual, str) and expected.casefold() in actual.casefold()
    if modifier == "startswith":
        return isinstance(actual, str) and actual.casefold().startswith(expected.casefold())
    if modifier == "endswith":
        return isinstance(actual, str) and actual.casefold().endswith(expected.casefold())
    if isinstance(actual, str) and isinstance(expected, str):
        if "*" in expected or "?" in expected:
            return fnmatch.fnmatchcase(actual.casefold(), expected.casefold())
        return actual.casefold() == expected.casefold()
    return type(actual) is type(expected) and actual == expected


def _is_integer_value(value: object) -> bool:
    if isinstance(value, int) and not isinstance(value, bool):
        return True
    return isinstance(value, str) and value.isdecimal()


def _is_attack_technique(value: str) -> bool:
    technique = value.casefold()
    if not technique.startswith("t"):
        return False
    identifier = technique[1:].split(".", 1)
    return len(identifier[0]) == 4 and identifier[0].isdigit() and (
        len(identifier) == 1
        or (len(identifier[1]) == 3 and identifier[1].isdigit())
    )
