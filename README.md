# Sentinel

Sentinel V0.1 is a local, read-only Windows system observer built as the first
layer of a personal defensive cybersecurity platform. It collects real system,
process, and network telemetry. It does **not** label activity as malicious,
block connections, terminate processes, or send data outside the computer.

## Why V0.1 exists

Security detection is only as trustworthy as its telemetry. This version keeps
the problem small enough to understand: collect operating-system facts, preserve
partial results when permissions or short-lived processes cause errors, and show
the result through a testable CLI.

```text
Windows host
    |
    +-- SystemCollector  ----+
    +-- ProcessCollector ----+--> typed CollectionResult --> CLI
    +-- NetworkCollector ----+             |
                                             +--> safe JSON application logs
```

The collectors do not call one another. Models do not know about presentation.
The CLI composes those pieces. This is enough separation to support later event
normalization without inventing a message bus, database, API, or service layer.

## Feature decisions

| Feature | Problem solved | Concepts learned | System and security value | Career value | Needed now? | How it is tested |
|---|---|---|---|---|---|---|
| Typed collection result | OS reads can partially fail | dataclasses, generics, contracts, UTC | prevents one inaccessible item from hiding all telemetry | backend and data contracts | Yes | success and partial-error unit tests |
| System collector | no concise host health view | CPU, RAM, disk, host identity | establishes system context and collector health | observability, DevOps, endpoint engineering | Yes | mocked metrics plus live `status` run |
| Process collector | no visibility into executing programs | PID, PPID, process tree, CPU sampling, memory | raw endpoint telemetry for later baselines | SOC, EDR, platform engineering | Yes | parent correlation and access-denied tests |
| Network collector | no process-to-socket view | TCP/UDP, local/remote endpoint, state, ports | raw context for later network detections | networking, SOC, cloud security | Yes | local connection and permission-failure tests |
| CLI | telemetry needs a usable interface | argument parsing, formatting, exit codes | manual inspection without a web attack surface | backend and operations tooling | Yes | CLI output tests and manual runs |
| Structured logging | silent failures make results misleading | levels, JSON, rotation, privacy | records application health without command lines or secrets | SRE, DevSecOps, incident diagnosis | Yes | tests exercise log creation; manual inspection |
| Database/API/dashboard/detection | no V0.1 problem requires them | later milestones | would add complexity before stable telemetry | valuable later | No | deferred until acceptance criteria exist |

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
```

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

- Collection is read-only and local.
- There is no persistence, service installation, packet capture, DNS interception,
  external lookup, blocking, quarantine, or automated response.
- Normal logs contain application health only, not process arguments or network rows.
- `.env`, virtual environments, caches, and runtime logs are ignored by Git.
- The tool should run with ordinary user privileges by default.

## Current limitations

- This is snapshot-based manual observation, not continuous monitoring.
- Network results are socket metadata, not packet contents or DNS history.
- Process CPU is a brief sample and not a long-term utilization measure.
- Processes can exit between enumeration and inspection.
- V0.1 has no baseline, event model, persistence, rules, risk score, or alerts.

## Definition of done for V0.1

- `sentinel status`, `sentinel processes`, and `sentinel network` run on Windows.
- Unit tests pass and OS failures are represented explicitly.
- Live output contains real telemetry and no fabricated security verdicts.
- README limitations and validation exercises are understood.
- The working tree is clean after the milestone commit.

## Next milestone (not implemented)

V0.2 will normalize selected telemetry into security events and store them in
SQLite. It should begin only after V0.1 behavior and concepts can be explained
without relying on the code as a black box.
