from datetime import datetime
import xml.etree.ElementTree as ET
from types import SimpleNamespace

from sentinel.storage import EventStore
from sentinel.windows_events import WindowsEventLogCollector


EVENT_TEMPLATE = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
  <Provider Name="Microsoft-Windows-Sysmon" />
  <EventID>{event_id}</EventID>
  <TimeCreated SystemTime="2026-11-17T12:00:00.000Z" />
  <EventRecordID>{record_id}</EventRecordID>
</System>
<EventData>{data}</EventData>
</Event>"""


def event_xml(event_id: int, record_id: int, data: str = "") -> str:
    return EVENT_TEMPLATE.format(event_id=event_id, record_id=record_id, data=data)


def test_system_service_events_keep_only_safe_service_metadata() -> None:
    installed = WindowsEventLogCollector._normalize(
        "System",
        104,
        7045,
        ET.fromstring(
            event_xml(
                7045,
                104,
                '<Data Name="ServiceName">ExampleService</Data>'
                '<Data Name="StartType">auto start</Data>'
                '<Data Name="ImagePath">C:\\Private\\service.exe --secret</Data>'
                '<Data Name="AccountName">DOMAIN\\private-user</Data>',
            )
        ),
    )
    start_type_changed = WindowsEventLogCollector._normalize(
        "System",
        105,
        7040,
        ET.fromstring(
            event_xml(
                7040,
                105,
                '<Data Name="param1">ExampleService</Data>'
                '<Data Name="param2">auto start</Data>'
                '<Data Name="param3">demand start</Data>',
            )
        ),
    )

    assert installed is not None
    assert installed.event_type == "system.service_installed"
    assert installed.source_event_id == 7045
    assert installed.details == {
        "record_id": 104,
        "event_id": 7045,
        "provider": "Microsoft-Windows-Sysmon",
        "service_name": "ExampleService",
        "start_type": "auto start",
    }
    assert start_type_changed is not None
    assert start_type_changed.event_type == "system.service_start_type_changed"
    assert start_type_changed.details["service_name"] == "ExampleService"


def test_sysmon_normalization_excludes_command_line_and_unapproved_fields() -> None:
    xml = event_xml(
        1,
        101,
        '<Data Name="ProcessId">4321</Data>'
        '<Data Name="Image">C:\\Apps\\sample.exe</Data>'
        '<Data Name="ParentProcessId">100</Data>'
        '<Data Name="ParentImage">C:\\Windows\\parent.exe</Data>'
        '<Data Name="CommandLine">sample.exe --secret</Data>'
        '<Data Name="User">TEST\\user</Data>',
    )
    root = ET.fromstring(xml)
    result = WindowsEventLogCollector._normalize(
        "Microsoft-Windows-Sysmon/Operational",
        101,
        1,
        root,
    )

    assert result is not None
    assert result.event_type == "process.created"
    assert result.process_id == 4321
    assert result.source_event_id == 1
    assert result.details == {
        "record_id": 101,
        "image": "C:\\Apps\\sample.exe",
        "parent_image": "C:\\Windows\\parent.exe",
        "parent_pid": 100,
    }


def test_sysmon_registry_events_keep_only_selected_autostart_metadata() -> None:
    xml = event_xml(
        13,
        102,
        '<Data Name="EventType">SetValue</Data>'
        '<Data Name="ProcessId">4321</Data>'
        '<Data Name="Image">C:\\Apps\\sample.exe</Data>'
        '<Data Name="TargetObject">'
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Sample"
        "</Data>"
        '<Data Name="Details">C:\\Users\\user\\private-data</Data>',
    )
    result = WindowsEventLogCollector._normalize(
        "Microsoft-Windows-Sysmon/Operational",
        102,
        13,
        ET.fromstring(xml),
    )

    assert result is not None
    assert result.event_type == "system.autostart_registry_changed"
    assert result.process_id == 4321
    assert result.source_event_id == 13
    assert result.details == {
        "record_id": 102,
        "registry_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Sample",
        "operation": "SetValue",
        "image": r"C:\Apps\sample.exe",
    }


def test_sysmon_registry_events_ignore_unmonitored_keys_and_map_service_paths() -> None:
    collector = WindowsEventLogCollector
    timestamp = ET.fromstring(event_xml(13, 103))
    timestamp_value = collector._system_attribute(timestamp, "TimeCreated", "SystemTime")
    assert timestamp_value is not None
    observed_at = datetime.fromisoformat(
        timestamp_value.replace("Z", "+00:00")
    )
    ignored = collector._normalize_registry_event(
        "Microsoft-Windows-Sysmon/Operational",
        103,
        13,
        observed_at,
        {"TargetObject": r"HKCU\Software\Sentinel\Preferences\Theme"},
    )
    service = collector._normalize_registry_event(
        "Microsoft-Windows-Sysmon/Operational",
        104,
        13,
        observed_at,
        {
            "TargetObject": (
                r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\Example"
            )
        },
    )

    assert ignored is None
    assert service is not None
    assert service.event_type == "system.service_registry_changed"


def test_security_process_events_exclude_command_line_and_user_fields() -> None:
    xml = event_xml(
        4688,
        105,
        '<Data Name="NewProcessId">0x10e1</Data>'
        '<Data Name="NewProcessName">C:\\Apps\\sample.exe</Data>'
        '<Data Name="ProcessId">0x3e8</Data>'
        '<Data Name="CommandLine">sample.exe --secret</Data>'
        '<Data Name="SubjectUserName">TEST\\user</Data>',
    )
    result = WindowsEventLogCollector._normalize(
        "Security",
        105,
        4688,
        ET.fromstring(xml),
    )

    assert result is not None
    assert result.event_type == "process.created"
    assert result.process_id == 4321
    assert result.details == {
        "record_id": 105,
        "image": "C:\\Apps\\sample.exe",
        "parent_pid": 1000,
    }


def test_windows_log_collector_checkpoints_and_ingests_only_selected_events(
    monkeypatch,
    tmp_path,
) -> None:
    store = EventStore(tmp_path / "events.db")
    collector = WindowsEventLogCollector()
    collector._wevtutil = "wevtutil.exe"
    latest = {
        "System": event_xml(6005, 5),
        "Security": event_xml(4624, 25),
        "Microsoft-Windows-Sysmon/Operational": event_xml(1, 10),
    }
    new_records = {
        "System": event_xml(6008, 6)
        + event_xml(
            7045,
            7,
            '<Data Name="ServiceName">ExampleService</Data>'
            '<Data Name="StartType">demand start</Data>'
            '<Data Name="ImagePath">C:\\Private\\service.exe</Data>',
        ),
        "Security": event_xml(
            4688,
            21,
            '<Data Name="NewProcessId">0x10e1</Data>'
            '<Data Name="NewProcessName">C:\\Apps\\sample.exe</Data>',
        ),
        "Microsoft-Windows-Sysmon/Operational": (
            event_xml(
                1,
                11,
                '<Data Name="ProcessId">4321</Data>'
                '<Data Name="Image">C:\\Apps\\sample.exe</Data>',
            )
        ),
    }

    def run(arguments, **kwargs):
        channel = arguments[2]
        is_latest = "/c:1" in arguments
        query = next(argument for argument in arguments if argument.startswith("/q:"))
        if not is_latest:
            assert "EventRecordID >" in query
            assert "EventID=" in query
            if channel == "System":
                assert "EventID=7040" in query
                assert "EventID=7045" in query
        return SimpleNamespace(
            returncode=0,
            stderr="",
            stdout=latest[channel] if is_latest else new_records[channel],
        )

    monkeypatch.setattr("sentinel.windows_events.subprocess.run", run)
    initial = collector.collect(store)
    store.persist_batch(initial.events, initial.checkpoints)
    next_result = collector.collect(store)

    assert initial.events == ()
    assert initial.errors == ()
    store.persist_batch(next_result.events, next_result.checkpoints)

    assert [(item.event_type, item.process_id) for item in next_result.events] == [
        ("windows.unexpected_shutdown", None),
        ("system.service_installed", None),
        ("process.created", 4321),
        ("process.created", 4321),
    ]
    assert store.get_checkpoint("System") == 7
    assert store.get_checkpoint("Security") == 25
    assert store.get_checkpoint("Microsoft-Windows-Sysmon/Operational") == 11


def test_missing_wevtutil_is_reported_as_unavailable(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    collector = WindowsEventLogCollector()
    collector._wevtutil = None

    result = collector.collect(store)

    assert result.events == ()
    assert result.errors[0].error_type == "SourceUnavailable"


def test_windows_log_checkpoint_reset_is_reported(monkeypatch, tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    store.set_checkpoint("System", 50)
    store.set_checkpoint("Microsoft-Windows-Sysmon/Operational", 10)
    collector = WindowsEventLogCollector()
    collector._wevtutil = "wevtutil.exe"

    def run(arguments, **kwargs):
        channel = arguments[2]
        latest_record = 20 if channel == "System" else 10
        return SimpleNamespace(
            returncode=0,
            stderr="",
            stdout=event_xml(6005, latest_record),
        )

    monkeypatch.setattr("sentinel.windows_events.subprocess.run", run)

    result = collector.collect(store)

    assert result.errors[0].error_type == "CheckpointReset"
    assert result.checkpoints["System"] == 20
    store.persist_batch(result.events, result.checkpoints)
    assert store.get_checkpoint("System") == 20


def test_inaccessible_security_log_does_not_stop_other_channels(
    monkeypatch,
    tmp_path,
) -> None:
    store = EventStore(tmp_path / "events.db")
    store.set_checkpoint("System", 5)
    store.set_checkpoint("Security", 10)
    collector = WindowsEventLogCollector()
    collector._wevtutil = "wevtutil.exe"

    def run(arguments, **kwargs):
        channel = arguments[2]
        is_latest = "/c:1" in arguments
        if channel == "Security":
            return SimpleNamespace(
                returncode=5,
                stderr="access denied",
                stdout="",
            )
        if channel == "System":
            content = event_xml(6005, 5) if is_latest else event_xml(6008, 6)
        else:
            content = event_xml(1, 8)
        return SimpleNamespace(returncode=0, stderr="", stdout=content)

    monkeypatch.setattr("sentinel.windows_events.subprocess.run", run)

    result = collector.collect(store)

    assert [item.event_type for item in result.events] == [
        "windows.unexpected_shutdown"
    ]
    assert [error.scope for error in result.errors] == ["windows.event_log.Security"]
    assert result.checkpoints == {
        "System": 6,
        "Microsoft-Windows-Sysmon/Operational": 8,
    }
