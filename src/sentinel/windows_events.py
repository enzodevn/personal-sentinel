"""Bounded, read-only ingestion of selected Windows Event Log records."""

from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime

from sentinel.models import CollectionError, SecurityEvent
from sentinel.storage import EventStore


MAX_RECORDS_PER_READ = 100
COMMAND_TIMEOUT_SECONDS = 10
CHANNEL_EVENT_IDS = {
    "System": {6005, 6006, 6008, 7040, 7045},
    "Security": {4688, 4689},
    "Microsoft-Windows-Sysmon/Operational": {1, 3, 12, 13, 14},
}
EVENT_XML_PATTERN = re.compile(r"<Event(?:\s[^>]*)?>.*?</Event\s*>", re.DOTALL)
ALLOWED_EVENT_DATA_FIELDS = {
    "ProcessId",
    "Image",
    "ParentProcessId",
    "ParentImage",
    "Protocol",
    "SourceIp",
    "SourcePort",
    "DestinationIp",
    "DestinationHostname",
    "DestinationPort",
    "TargetObject",
    "EventType",
    "NewProcessId",
    "NewProcessName",
    "ProcessName",
}
AUTOSTART_REGISTRY_PREFIXES = (
    r"HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN",
    r"HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE",
    r"HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN",
    r"HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE",
    r"HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN",
    r"HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE",
    r"HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\EXPLORER\RUN",
    r"HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\EXPLORER\RUN",
    r"HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\STARTUPAPPROVED\RUN",
    r"HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\STARTUPAPPROVED\RUN32",
    r"HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\STARTUPAPPROVED\RUN",
    r"HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\STARTUPAPPROVED\RUN32",
    r"HKLM\SYSTEM\CURRENTCONTROLSET\SERVICES",
    r"HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNSERVICES",
    r"HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNSERVICESONCE",
)


@dataclass(frozen=True, slots=True)
class WindowsEventBatch:
    events: tuple[SecurityEvent, ...]
    checkpoints: dict[str, int]
    errors: tuple[CollectionError, ...]


class WindowsEventLogCollector:
    """Read new System and optional Sysmon events using Windows' wevtutil."""

    def __init__(self) -> None:
        self._wevtutil = shutil.which("wevtutil.exe") or shutil.which("wevtutil")

    def collect(self, store: EventStore) -> WindowsEventBatch:
        if self._wevtutil is None:
            error = CollectionError(
                scope="windows.event_log",
                error_type="SourceUnavailable",
                message="wevtutil was not found; Windows Event Log is unavailable.",
            )
            return WindowsEventBatch(events=(), checkpoints={}, errors=(error,))

        events: list[SecurityEvent] = []
        errors: list[CollectionError] = []
        checkpoints: dict[str, int] = {}
        for channel, allowed_ids in CHANNEL_EVENT_IDS.items():
            try:
                checkpoint = store.get_checkpoint(channel)
                if checkpoint is None:
                    latest = self._query(channel, latest=True)
                    checkpoints[channel] = max(
                        (record_id for record_id, _, _ in latest),
                        default=0,
                    )
                    continue

                latest = self._query(channel, latest=True)
                latest_record_id = max(
                    (record_id for record_id, _, _ in latest),
                    default=0,
                )
                if latest_record_id < checkpoint:
                    checkpoints[channel] = latest_record_id
                    errors.append(
                        CollectionError(
                            scope=f"windows.event_log.{channel}",
                            error_type="CheckpointReset",
                            message=(
                                "The channel record ID moved backwards; its "
                                "checkpoint was reset."
                            ),
                        )
                    )
                    continue

                records = self._query(
                    channel,
                    after_record_id=checkpoint,
                    event_ids=allowed_ids,
                )
                for record_id, event_id, root in records:
                    if event_id not in allowed_ids:
                        continue
                    try:
                        event = self._normalize(channel, record_id, event_id, root)
                    except ValueError as error:
                        errors.append(
                            CollectionError.from_exception(
                                f"windows.event_log.{channel}.{record_id}",
                                error,
                            )
                        )
                        continue
                    if event is not None:
                        events.append(event)
                if len(records) < MAX_RECORDS_PER_READ:
                    new_checkpoint = max(
                        latest_record_id,
                        max((record_id for record_id, _, _ in records), default=0),
                    )
                else:
                    new_checkpoint = max(record_id for record_id, _, _ in records)
                if new_checkpoint > checkpoint:
                    checkpoints[channel] = new_checkpoint
            except (OSError, subprocess.SubprocessError, ET.ParseError, ValueError) as error:
                errors.append(
                    CollectionError.from_exception(f"windows.event_log.{channel}", error)
                )
        return WindowsEventBatch(
            events=tuple(events),
            checkpoints=checkpoints,
            errors=tuple(errors),
        )

    def _query(
        self,
        channel: str,
        *,
        latest: bool = False,
        after_record_id: int | None = None,
        event_ids: set[int] | None = None,
    ) -> list[tuple[int, int, ET.Element]]:
        if latest:
            query = "*"
            count = 1
            reverse = "true"
        else:
            if after_record_id is None:
                raise ValueError("after_record_id is required for incremental queries")
            if not event_ids:
                raise ValueError("event_ids are required for incremental queries")
            event_filter = " or ".join(
                f"EventID={event_id}" for event_id in sorted(event_ids)
            )
            query = (
                f"*[System[(EventRecordID > {after_record_id}) "
                f"and ({event_filter})]]"
            )
            count = MAX_RECORDS_PER_READ
            reverse = "false"
        completed = subprocess.run(
            [
                self._wevtutil,
                "qe",
                channel,
                f"/q:{query}",
                "/f:xml",
                f"/c:{count}",
                f"/rd:{reverse}",
            ],
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
        if completed.returncode:
            raise OSError(
                f"wevtutil exited with code {completed.returncode} "
                f"while querying {channel}."
            )

        records: list[tuple[int, int, ET.Element]] = []
        for xml_event in EVENT_XML_PATTERN.findall(completed.stdout):
            root = ET.fromstring(xml_event)
            record_id = self._system_value(root, "EventRecordID")
            event_id = self._system_value(root, "EventID")
            if record_id is not None and event_id is not None:
                records.append((int(record_id), int(event_id), root))
        return records

    @classmethod
    def _normalize(
        cls,
        channel: str,
        record_id: int,
        event_id: int,
        root: ET.Element,
    ) -> SecurityEvent | None:
        timestamp_text = cls._system_attribute(root, "TimeCreated", "SystemTime")
        if timestamp_text is None:
            raise ValueError("Selected event is missing its timestamp.")
        try:
            timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("Selected event has an invalid timestamp.") from error
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)

        if channel == "System":
            event_types = {
                6005: "windows.event_log_service_started",
                6006: "windows.event_log_service_stopped",
                6008: "windows.unexpected_shutdown",
                7040: "system.service_start_type_changed",
                7045: "system.service_installed",
            }
            event_type = event_types.get(event_id)
            if event_type is None:
                return None
            details: dict[str, str | int | float | bool | None] = {
                "record_id": record_id,
                "event_id": event_id,
            }
            provider = cls._system_attribute(root, "Provider", "Name")
            if provider:
                details["provider"] = provider
            if event_id in {7040, 7045}:
                event_data = cls._event_data(root)
                service_name = event_data.get("ServiceName")
                if event_id == 7040:
                    service_name = service_name or event_data.get("param1")
                if service_name:
                    details["service_name"] = service_name
                if event_id == 7045 and event_data.get("StartType"):
                    details["start_type"] = event_data["StartType"]
            return SecurityEvent(
                event_id=f"windows:{channel}:{record_id}",
                source=channel,
                event_type=event_type,
                timestamp=timestamp,
                process_id=None,
                details=details,
            )

        raw_fields = {
            name: value
            for name, value in cls._event_data(root).items()
            if name in ALLOWED_EVENT_DATA_FIELDS
        }
        if channel == "Security":
            process_id_value = (
                raw_fields.get("NewProcessId")
                if event_id == 4688
                else raw_fields.get("ProcessId")
            )
            process_id = cls._integer(process_id_value)
            process_name = (
                raw_fields.get("NewProcessName")
                if event_id == 4688
                else raw_fields.get("ProcessName")
            )
            if event_id == 4688:
                event_type = "process.created"
            elif event_id == 4689:
                event_type = "process.exited"
            else:
                return None
            details = {"record_id": record_id}
            if process_name:
                details["image"] = process_name
            if event_id == 4688:
                parent_pid = cls._integer(raw_fields.get("ProcessId"))
                if parent_pid is not None:
                    details["parent_pid"] = parent_pid
            return SecurityEvent(
                event_id=f"windows:{channel}:{record_id}",
                source=channel,
                event_type=event_type,
                timestamp=timestamp,
                process_id=process_id,
                details=details,
            )

        if event_id in {12, 13, 14}:
            return cls._normalize_registry_event(
                channel,
                record_id,
                event_id,
                timestamp,
                raw_fields,
            )
        process_id = cls._integer(raw_fields.get("ProcessId"))
        detail_fields = {
            "Image": "image",
            "ParentImage": "parent_image",
            "Protocol": "protocol",
            "SourceIp": "source_ip",
            "SourcePort": "source_port",
            "DestinationIp": "destination_ip",
            "DestinationHostname": "destination_hostname",
            "DestinationPort": "destination_port",
        }
        normalized: dict[str, str | int | float | bool | None] = {
            "record_id": record_id
        }
        for field_name, key in detail_fields.items():
            value = raw_fields.get(field_name)
            if value is not None:
                normalized[key] = (
                    cls._integer(value) if field_name.endswith("Port") else value
                )
        parent_pid = cls._integer(raw_fields.get("ParentProcessId"))
        if parent_pid is not None:
            normalized["parent_pid"] = parent_pid
        if event_id == 1:
            event_type = "process.created"
        elif event_id == 3:
            event_type = "network.connection_observed"
        else:
            return None
        return SecurityEvent(
            event_id=f"windows:{channel}:{record_id}",
            source=channel,
            event_type=event_type,
            timestamp=timestamp,
            process_id=process_id,
            details=normalized,
        )

    @classmethod
    def _normalize_registry_event(
        cls,
        channel: str,
        record_id: int,
        event_id: int,
        timestamp: datetime,
        raw_fields: dict[str, str],
    ) -> SecurityEvent | None:
        target = raw_fields.get("TargetObject")
        if target is None:
            raise ValueError("Registry event is missing its target path.")
        normalized_target = cls._canonical_registry_path(target)
        if not cls._is_monitored_registry_path(normalized_target):
            return None

        service_prefix = r"HKLM\SYSTEM\CURRENTCONTROLSET\SERVICES"
        event_type = (
            "system.service_registry_changed"
            if cls._matches_registry_prefix(normalized_target, service_prefix)
            else "system.autostart_registry_changed"
        )
        operation = raw_fields.get("EventType") or {
            12: "key_created_or_deleted",
            13: "value_set",
            14: "key_renamed",
        }[event_id]
        details: dict[str, str | int | float | bool | None] = {
            "record_id": record_id,
            "registry_path": target,
            "operation": operation,
        }
        image = raw_fields.get("Image")
        if image:
            details["image"] = image
        process_id = cls._integer(raw_fields.get("ProcessId"))
        return SecurityEvent(
            event_id=f"windows:{channel}:{record_id}",
            source=channel,
            event_type=event_type,
            timestamp=timestamp,
            process_id=process_id,
            details=details,
        )

    @classmethod
    def _canonical_registry_path(cls, path: str) -> str:
        normalized = path.replace("/", "\\").strip("\\").upper()
        if normalized.startswith("REGISTRY\\MACHINE\\"):
            return "HKLM\\" + normalized[len("REGISTRY\\MACHINE\\") :]
        if normalized.startswith("REGISTRY\\USER\\"):
            parts = normalized.split("\\", 3)
            if len(parts) == 4:
                return "HKCU\\" + parts[3]
        if normalized.startswith("HKU\\"):
            parts = normalized.split("\\", 2)
            if len(parts) == 3:
                return "HKCU\\" + parts[2]
        return normalized

    @classmethod
    def _is_monitored_registry_path(cls, path: str) -> bool:
        return any(
            cls._matches_registry_prefix(path, prefix)
            for prefix in AUTOSTART_REGISTRY_PREFIXES
        )

    @staticmethod
    def _matches_registry_prefix(path: str, prefix: str) -> bool:
        return path == prefix or path.startswith(prefix + "\\")

    @staticmethod
    def _event_data(root: ET.Element) -> dict[str, str]:
        data: dict[str, str] = {}
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] == "Data":
                name = element.attrib.get("Name")
                if name and element.text:
                    data[name] = element.text
        return data

    @staticmethod
    def _system_value(root: ET.Element, name: str) -> str | None:
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] == name and element.text:
                return element.text
        return None

    @staticmethod
    def _system_attribute(root: ET.Element, name: str, attribute: str) -> str | None:
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] == name:
                return element.attrib.get(attribute)
        return None

    @staticmethod
    def _integer(value: str | None) -> int | None:
        if value is None:
            return None
        try:
            return int(value, 0)
        except ValueError:
            try:
                return int(value)
            except ValueError:
                return None
