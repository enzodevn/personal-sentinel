# Personal Sentinel

Personal Sentinel V0.3 builds on the read-only V0.1 collectors and V0.2
monitoring pipeline with local, explainable detection and risk prioritization.
Selected events and findings are stored in a local SQLite database. It does
**not** label activity as malicious, block connections, terminate processes, or
send data outside the computer.

## Why V0.2 exists

Security detection is only as trustworthy as its telemetry. V0.2 adds a small,
auditable event pipeline: take read-only snapshots, ingest selected Windows
events when available, normalize them, and retain a bounded local history.

```text
Windows host
    |
    +-- SystemCollector  -----+
    +-- ProcessCollector -----+--> typed results --> CLI
    +-- NetworkCollector -----+          |
                                         +--> ProcessDeltaMonitor
                                         +--> NetworkDeltaMonitor
                                         +--> WindowsEventLogCollector
                                                  |
                                                  v
                                           local SQLite EventStore
```

The collectors do not call one another. Models do not know about presentation.
The CLI composes the collectors and monitor. There is no service installation,
message broker, network API, or dashboard.

## Feature decisions

| Feature | Problem solved | Concepts learned | System and security value | Career value | Needed now? | How it is tested |
|---|---|---|---|---|---|---|
| Typed collection result | OS reads can partially fail | dataclasses, generics, contracts, UTC | prevents one inaccessible item from hiding all telemetry | backend and data contracts | Yes | success and partial-error unit tests |
| System collector | no concise host health view | CPU, RAM, disk, host identity | establishes system context and collector health | observability, DevOps, endpoint engineering | Yes | mocked metrics plus live `status` run |
| Process collector | no visibility into executing programs | PID, PPID, process tree, CPU sampling, memory | raw endpoint telemetry for later baselines | SOC, EDR, platform engineering | Yes | parent correlation and access-denied tests |
| Network collector | no process-to-socket view | TCP/UDP, local/remote endpoint, state, ports | raw context for later network detections | networking, SOC, cloud security | Yes | local connection and permission-failure tests |
| CLI | telemetry needs a usable interface | argument parsing, formatting, exit codes | manual inspection without a web attack surface | backend and operations tooling | Yes | CLI output tests and manual runs |
| Structured logging | silent failures make results misleading | levels, JSON, rotation, privacy | records application health without command lines or secrets | SRE, DevSecOps, incident diagnosis | Yes | tests exercise log creation; manual inspection |
| Event model and SQLite store | telemetry needs a local history | event schemas, SQL, retention | bounded local records with deduplication | data engineering, endpoint telemetry | Yes (V0.2) | round-trip, duplicate, retention tests |
| Process delta monitoring | snapshots alone lose lifecycle changes | baselines, PID reuse, polling | records observed starts/exits without claiming malice | EDR and SOC engineering | Yes (V0.2) | synthetic process snapshots |
| Network delta monitoring | socket snapshots lose endpoint changes | endpoint identity, polling, partial results | records observed endpoint open/close transitions without inspecting packets | network and SOC engineering | Yes (V0.2) | synthetic socket snapshots |
| Windows Event Log | selected OS events need history | channels, event IDs, checkpoints | reads selected System host/service lifecycle, Security process, and optional Sysmon process, network, and registry events | Windows security engineering | Yes (V0.2) | XML parsing and checkpoint tests |
| Explainable detection and risk | raw events need consistent review priorities | rule contracts, evidence quality, weighted scoring | describes observed activity without asserting malware or probability | detection and SOC engineering | Yes (V0.3) | deterministic rules and risk tests |
| Local Sigma rules | custom detections need a familiar format | YAML validation, mapping, safe condition evaluation | supports a bounded subset over fields Sentinel already collects | detection engineering | Yes (V0.3) | parser rejection and synthetic match tests |
| Temporal correlation | related events need bounded context | event windows, stable identities, correlation | relates selected Sysmon process and autostart events for the same PID | detection engineering | Yes (V0.3) | time-window, PID, and evidence tests |
| Stored alerts and CLI | findings need reviewable history | SQLite migrations, idempotency, explainability | atomically stores and displays bounded findings with evidence | SOC tooling and data engineering | Yes (V0.3) | migration, retention, pipeline, and CLI tests |

## Prerequisites

- Windows 10 or 11
- Python 3.12 or newer
- Git

Some network ownership details can require an elevated terminal. Sentinel treats
missing permissions as a warning; elevation is not required for normal learning.
Do not run as Administrator merely to remove a harmless warning.

## Setup (PowerShell)

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

If `py` is unavailable, install Python 3.12+ from python.org and enable the
Python launcher during setup. The current repository was validated with the
official Python 3.14.7 distribution.

## Usage

```powershell
sentinel status
sentinel processes
sentinel processes --limit 20
sentinel network
sentinel network --limit 30
sentinel monitor --once
sentinel monitor --interval 5
sentinel monitor --sigma-rules .\rules
sentinel events --limit 20
sentinel alerts --limit 20
```

`monitor` runs in the foreground until Ctrl+C. `--once` performs one collection
cycle and exits; the first cycle establishes process and network baselines and
skips older Windows Event Log records. The default database is `data/sentinel.db`.
Configure retention with `--retention-days`; the store also limits history to
100,000 events, so high event volume can make the actual history shorter than
the configured age limit. Alerts use the same age retention and are capped at
20,000 records. Use `--database` on the monitor, events, and alerts commands to
choose another local path. `--sigma-rules` accepts a local YAML file or folder;
Sentinel does not download rules.

Application-health logs are written as JSON lines to `logs/sentinel.log` in the
current directory. Set `SENTINEL_LOG_DIR` to choose a different local directory.
Process command lines are held in the in-memory model but are not printed or
logged by V0.1 because arguments can contain credentials.

### How to read the data

- `PID` identifies a process; it can be reused after a process exits.
- `PPID` is the parent PID. A relationship is context, not proof of maliciousness.
- Per-process CPU is sampled over a short interval and will vary between runs.
- Per-process CPU can exceed 100% when work spans multiple logical CPU cores.
- `LOCAL` is this computer's socket endpoint; `REMOTE` is its peer when one exists.
- `LISTEN` means a TCP socket is waiting for connections. It is not automatically a risk.
- UDP has no TCP-style connection state, so it is displayed as `NONE`.
- A missing path, username, owner, or connection is commonly a permissions or timing issue.

## Tests

```powershell
python -m pytest
```

The tests replace operating-system calls with controlled examples. This makes
success, process exit, permission failure, parent correlation, and CLI behavior
repeatable without creating suspicious activity.

## Manual learning lab

1. Run `sentinel status` twice. Explain why CPU changes while host identity does not.
2. Run `sentinel processes --limit 30`. Find Sentinel's Python process and identify its PPID.
3. Open Notepad, run the process command again, and explain the new PID without calling it a threat.
4. Start a local-only server with `python -m http.server 8765 --bind 127.0.0.1` in a second terminal.
5. Run `sentinel network`, find port `8765`, and identify `LOCAL`, `REMOTE`, `LISTEN`, and the owner PID.
6. Stop the local server with `Ctrl+C`, rerun the command, and explain the change.

You understand the milestone when you can predict these observations, explain
why a short-lived process may disappear during collection, and describe why a
single unusual process or port is evidence to investigate—not a malware verdict.

## Security and privacy boundaries

- Collection is read-only and local; monitoring is opt-in and runs in the foreground.
- There is no persistence, service installation, packet capture, DNS interception,
  external lookup, blocking, quarantine, or automated response.
- Normal logs contain application health only, not process arguments or network rows.
- The event store excludes process command lines, event-log user fields, and
  Registry value contents. It is an ordinary, unencrypted SQLite database;
  protect the chosen folder accordingly.
- Detection records retain rule metadata and only fields selected as evidence.
  Alert scores prioritize review; they are not probabilities or malware
  verdicts. Sentinel takes no automatic response action.
- The local event store includes observed socket endpoints (addresses, ports,
  state, PID, and process name); it does not capture packets or DNS history.
- Windows Event Log cursors start at the newest record on first use, so old records
  are not imported. Missing channels or permissions are reported as collection
  warnings; Sysmon is optional and is never installed or configured by Sentinel.
- Only selected System events (6005, 6006, 6008, 7040, 7045), Security events
  (4688, 4689), and Sysmon events (1, 3, 12, 13, 14) are ingested. System 7040
  and 7045 report service start-type changes and installations. Service names
  are retained; System 7045 also stores the start type, but not executable paths
  or account names.
  Security process events require the corresponding Windows audit policy and
  may require additional permissions; Sentinel never changes audit settings.
  Events 6005/6006 describe the Event Log service lifecycle, not definitive host
  startup/shutdown. Registry events are restricted to selected startup and
  service keys, and value contents are not stored. This is not full event-log
  archiving.
- `.env`, virtual environments, caches, and runtime logs are ignored by Git.
- The tool should run with ordinary user privileges by default.

## Current limitations

- System and manual network commands remain snapshots; continuous monitoring
  records process lifecycle and network endpoint deltas plus selected Windows
  events.
- Network results are socket metadata, not packet contents or DNS history.
- TCP teardown states such as `CLOSE`, `FIN_WAIT`, and `TIME_WAIT` are not
  reported as new endpoint openings; a previously observed endpoint is reported
  closed when it enters teardown.
- Process CPU is a brief sample and not a long-term utilization measure.
- Processes can exit between enumeration and inspection.
- Process lifecycle events require a readable process and creation time. The
  first process and network scans establish baselines and do not generate
  lifecycle events.
- Windows Event Log polling is bounded to 100 records per channel per cycle.
- V0.3 adds a local detection engine, risk prioritization, event correlation,
  optional Sigma rules, and stored explainable alerts.

## V0.2 status

Implemented in this milestone: typed normalized events, local SQLite storage,
retention and deduplication, process and network lifecycle polling, and bounded
ingestion of selected System, Security, and optional Sysmon events, including
service and startup-related changes.

On the validation host, `sentinel monitor --once` completed successfully and
read the System channel. Security access was denied (`wevtutil` code 5), and the
Sysmon channel was absent (code 15007); the monitor reported both as warnings
and continued. Missing and inaccessible sources are covered by tests, but live
Security and Sysmon event ingestion was not verified on this host. No audit
policy was changed and Sysmon was not installed or configured. System service
event normalization is covered by tests; whether those events occur depends on
host activity.

A network-only five-minute run at a five-second interval observed 1,520 endpoint
events. This is a workload-specific sample, not a general expected rate.

To try the foreground monitor on Windows:

```powershell
sentinel monitor --interval 5
```

In another terminal, inspect its local history:

```powershell
sentinel events --limit 20
```

The first process and network scans establish baselines; lifecycle events appear
only after a later snapshot observes a change. If an optional Windows event
channel is missing or inaccessible, Sentinel reports a warning and continues
with available sources.

## Definition of done for V0.1

- `sentinel status`, `sentinel processes`, and `sentinel network` run on Windows.
- Unit tests pass and OS failures are represented explicitly.
- Live output contains real telemetry and no fabricated security verdicts.
- README limitations and validation exercises are understood.
- The working tree is clean after the milestone commit.

## Further V0.2 validation

To validate Security and Sysmon event ingestion live, use a Windows environment
where those channels and permissions are already available. Sentinel does not
change audit policy or install/configure Sysmon. V0.3 detections use only
telemetry that the host allows Sentinel to collect.

## V0.3 status (complete)

The deterministic rule engine evaluates selected autostart-registry and
Windows service changes already collected by V0.2. It also supports local
Sigma YAML rules and correlates a Sysmon process-creation event with a
monitored autostart registry change when both have the same PID and occur within
five minutes. Correlation uses a bounded recent event window. Findings retain
the rule ID and version, match criteria, selected event evidence, source event
IDs where available, optional MITRE ATT&CK technique, and defensive review
guidance. These changes can be legitimate; a finding is not a malware verdict.

The risk score is a 0–100 prioritization score, not a probability of infection:

```text
30% severity + 25% confidence + 20% impact
+ 15% evidence quality + 10% context
```

Severity is mapped to 0, 25, 50, 75, or 100 for informational, low, moderate,
high, or critical. Evidence quality is the percentage of rule-declared fields
present in the matched event. Default score bands are informational (0–19),
low (20–39), moderate (40–59), high (60–79), and critical (80–100); the weights
and band limits are configurable in code. Each rule declares its severity,
confidence, impact, and context inputs. Confidence describes the strength of
the rule signal, not the likelihood of infection.

Monitor cycles persist telemetry, detections, and Windows Event Log checkpoints
atomically. Stable detection IDs make repeated findings idempotent; schema
migrations preserve existing event history. `sentinel alerts` displays stored
findings, criteria, evidence, and review recommendations. Supported Sigma rules
are validated locally with pySigma and are limited to Sentinel's mapped Windows
event sources, collected fields, and supported condition/modifier subset.
Sigma correlation rules, unsupported fields, and fields that Sentinel omits
for privacy (such as command lines) are rejected explicitly.

Security and Sysmon live ingestion remain subject to the permissions and
channel availability described above. If a required channel is missing or
inaccessible, the monitor reports the collection warning and continues with
available sources. No response actions are taken.
