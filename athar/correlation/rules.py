"""
athar.correlation.rules
~~~~~~~~~~~~~~~~~~~~~~~
Correlation rules for the Athar DFIR engine.

Each rule is an independent function that accepts the full list of artefact
records and returns a list of CorrelatedEvent objects for matching patterns.

Rules are designed to be:
- Independent: no rule depends on another rule's output
- Additive: multiple rules may fire on the same records
- Conservative: false negatives are preferable to false positives

Rule inventory:
    rule_lolbin_execution        LOLBin detected in Prefetch or Event 4688
    rule_execution_of_new_file   File created and executed within 60s
    rule_timestomp               Timestomped file executed
    rule_log_cleared             Audit log cleared (Event 1102)
    rule_service_install         Service installed (Event 7045/4697 + file)
    rule_scheduled_task          Scheduled task created/modified (Event 4698/4702)
    rule_executable_dropped      New file created and executed (MFT + Prefetch)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from athar.models.base import BaseRecord, CorrelatedEvent, EventType
from athar.models.mft import MFTRecord
from athar.models.prefetch import PrefetchRecord
from athar.models.evtx import EventLogRecord
from athar.models.usn import USNRecord
from athar.correlation.enrichment import is_lolbin, get_lolbin_mitre, LOLBIN_MITRE

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_60S = timedelta(seconds=60)
_120S = timedelta(seconds=120)
_10M = timedelta(minutes=10)


def _within(ts1: datetime, ts2: datetime, window: timedelta) -> bool:
    """Return True if ts1 and ts2 are within `window` of each other."""
    return abs(ts1 - ts2) <= window


def _make_event(
    records: list[BaseRecord],
    tags: list[str],
    confidence: str,
    notes: list[str],
    mitre_tags: list[str],
    rule_id: str,
    primary_path: str = "",
) -> CorrelatedEvent:
    """Construct a CorrelatedEvent from a list of records."""
    timestamps = [r.timestamp for r in records]
    path = primary_path or (records[0].path if records else "")
    filename = records[0].filename if records else ""
    return CorrelatedEvent(
        window_start=min(timestamps),
        window_end=max(timestamps),
        primary_path=path,
        primary_filename=filename,
        records=records,
        tags=tags,
        confidence=confidence,
        notes=notes,
        mitre_tags=mitre_tags,
        rule_id=rule_id,
    )


# ---------------------------------------------------------------------------
# Rule 1: LOLBin execution
# ---------------------------------------------------------------------------

def rule_lolbin_execution(records: list[BaseRecord]) -> list[CorrelatedEvent]:
    """
    Detect execution of Living-off-the-Land Binaries.

    Fires on any Prefetch record or Event 4688 where the filename matches
    a known LOLBin. Each unique (binary, timestamp) pair generates one event.

    Confidence: high
    MITRE: T1218 (or specific subtechnique based on binary)
    """
    events: list[CorrelatedEvent] = []

    for r in records:
        if r.source not in ("prefetch", "evtx"):
            continue
        if r.source == "evtx" and isinstance(r, EventLogRecord) and r.event_id != 4688:
            continue
        if r.event_type not in (EventType.EXECUTION, EventType.PROCESS_CREATE):
            continue

        if not is_lolbin(r.filename):
            continue

        mitre = get_lolbin_mitre(r.filename) or "T1218"

        events.append(_make_event(
            records=[r],
            tags=["lolbin_execution", r.event_type],
            confidence="high",
            notes=[
                f"LOLBin executed: {r.filename} at {r.timestamp.isoformat()}",
                f"Source: {r.source}",
            ],
            mitre_tags=[mitre],
            rule_id="rule_lolbin_execution",
            primary_path=r.path,
        ))

    log.debug("rule_lolbin_execution: %d findings", len(events))
    return events


# ---------------------------------------------------------------------------
# Rule 2: Execution of a newly created file
# ---------------------------------------------------------------------------

def rule_execution_of_new_file(records: list[BaseRecord]) -> list[CorrelatedEvent]:
    """
    Detect a file being created and executed within 60 seconds.

    Correlates:
    - USN FILE_CREATE event
    - Prefetch execution record for the same filename

    Confidence: high
    MITRE: T1204.002
    """
    events: list[CorrelatedEvent] = []

    usn_creates = [
        r for r in records
        if isinstance(r, USNRecord) and "FILE_CREATE" in r.reason_flags
    ]
    executions = [
        r for r in records
        if r.source == "prefetch" and r.event_type == EventType.EXECUTION
    ]

    for exec_r in executions:
        for usn_r in usn_creates:
            if exec_r.filename != usn_r.filename:
                continue
            if not _within(exec_r.timestamp, usn_r.timestamp, _60S):
                continue

            delta = abs((exec_r.timestamp - usn_r.timestamp).total_seconds())
            events.append(_make_event(
                records=[usn_r, exec_r],
                tags=["execution", "new_file", "execution_of_new_file"],
                confidence="high",
                notes=[
                    f"File created and executed within {delta:.1f}s: {exec_r.filename}",
                    f"Created at: {usn_r.timestamp.isoformat()} (USN)",
                    f"Executed at: {exec_r.timestamp.isoformat()} (Prefetch)",
                ],
                mitre_tags=["T1204.002"],
                rule_id="rule_execution_of_new_file",
                primary_path=exec_r.path,
            ))

    log.debug("rule_execution_of_new_file: %d findings", len(events))
    return events


# ---------------------------------------------------------------------------
# Rule 3: Timestomping
# ---------------------------------------------------------------------------

def rule_timestomp(records: list[BaseRecord]) -> list[CorrelatedEvent]:
    """
    Detect possible timestamp manipulation (timestomping).

    Fires when an MFT record has timestomp_suspect=True and there is a
    corresponding Prefetch execution record for the same filename.

    Confidence: high
    MITRE: T1070.006
    """
    events: list[CorrelatedEvent] = []

    mft_suspects = [
        r for r in records
        if isinstance(r, MFTRecord) and r.timestomp_suspect
    ]
    executions = [
        r for r in records
        if r.source == "prefetch" and r.event_type == EventType.EXECUTION
    ]

    for mft_r in mft_suspects:
        for exec_r in executions:
            if mft_r.filename != exec_r.filename:
                continue

            si = mft_r.si_created
            fn = mft_r.fn_created
            delta = abs((si - fn).total_seconds()) if si and fn else 0

            events.append(_make_event(
                records=[mft_r, exec_r],
                tags=["timestomping", "execution", "defence_evasion"],
                confidence="high",
                notes=[
                    f"Possible timestomping detected: {mft_r.filename}",
                    f"$SI created:  {si.isoformat() if si else 'N/A'}",
                    f"$FN created:  {fn.isoformat() if fn else 'N/A'}",
                    f"Divergence:   {delta:.1f}s",
                    f"Executed at:  {exec_r.timestamp.isoformat()} (Prefetch)",
                ],
                mitre_tags=["T1070.006"],
                rule_id="rule_timestomp",
                primary_path=mft_r.path,
            ))

    log.debug("rule_timestomp: %d findings", len(events))
    return events


# ---------------------------------------------------------------------------
# Rule 4: Audit log cleared
# ---------------------------------------------------------------------------

def rule_log_cleared(records: list[BaseRecord]) -> list[CorrelatedEvent]:
    """
    Detect audit log clearing events (Event 1102).

    Checks for any execution activity within 10 minutes after the log clear.
    Confidence is high if subsequent activity is found, medium if isolated.

    MITRE: T1070.001
    """
    events: list[CorrelatedEvent] = []

    log_clears = [
        r for r in records
        if isinstance(r, EventLogRecord) and r.event_id == 1102
    ]

    executions = [
        r for r in records
        if r.event_type in (EventType.EXECUTION, EventType.PROCESS_CREATE)
    ]

    for clear_r in log_clears:
        # Find executions within 10 minutes after the log clear
        subsequent = [
            r for r in executions
            if clear_r.timestamp <= r.timestamp <= clear_r.timestamp + _10M
        ]

        subject = clear_r.event_data.get("SubjectUserName", "unknown")
        domain = clear_r.event_data.get("SubjectDomainName", "")
        actor = f"{domain}\\{subject}" if domain else subject

        if subsequent:
            confidence = "high"
            notes = [
                f"Audit log cleared by {actor} at {clear_r.timestamp.isoformat()}",
                f"Followed by {len(subsequent)} execution event(s) within 10 minutes",
                f"First post-clear execution: {subsequent[0].filename} at {subsequent[0].timestamp.isoformat()}",
            ]
            contributing = [clear_r] + subsequent[:5]  # cap record list
        else:
            confidence = "medium"
            notes = [
                f"Audit log cleared by {actor} at {clear_r.timestamp.isoformat()}",
                "No executions detected within 10 minutes after log clear",
            ]
            contributing = [clear_r]

        events.append(_make_event(
            records=contributing,
            tags=["log_cleared", "defence_evasion"],
            confidence=confidence,
            notes=notes,
            mitre_tags=["T1070.001"],
            rule_id="rule_log_cleared",
            primary_path=clear_r.path,
        ))

    log.debug("rule_log_cleared: %d findings", len(events))
    return events


# ---------------------------------------------------------------------------
# Rule 5: Service installation
# ---------------------------------------------------------------------------

def rule_service_install(records: list[BaseRecord]) -> list[CorrelatedEvent]:
    """
    Detect service installation events (Event 7045 or 4697).

    Correlates with USN or MFT file creation for the service binary within ±120s.

    Confidence: high
    MITRE: T1543.003
    """
    events: list[CorrelatedEvent] = []

    service_events = [
        r for r in records
        if isinstance(r, EventLogRecord) and r.event_id in (7045, 4697)
    ]

    file_creates = [
        r for r in records
        if r.event_type == EventType.FILE_CREATE
    ]

    for svc_r in service_events:
        service_name = svc_r.event_data.get("ServiceName", "unknown")
        image_path = svc_r.event_data.get("ImagePath", "") or svc_r.event_data.get("ServiceFileName", "")
        svc_filename = svc_r.filename or (image_path.split("\\")[-1].upper() if image_path else "")

        # Look for file creation of service binary
        correlated_files = [
            r for r in file_creates
            if svc_filename and r.filename == svc_filename
            and _within(svc_r.timestamp, r.timestamp, _120S)
        ]

        contributing = [svc_r] + correlated_files
        notes = [
            f"Service installed: {service_name} (Event {svc_r.event_id})",
            f"Image path: {image_path or 'N/A'}",
            f"Timestamp: {svc_r.timestamp.isoformat()}",
        ]
        if correlated_files:
            notes.append(
                f"Service binary file creation confirmed at {correlated_files[0].timestamp.isoformat()}"
            )

        events.append(_make_event(
            records=contributing,
            tags=["service_install", "persistence"],
            confidence="high",
            notes=notes,
            mitre_tags=["T1543.003"],
            rule_id="rule_service_install",
            primary_path=svc_r.path or image_path,
        ))

    log.debug("rule_service_install: %d findings", len(events))
    return events


# ---------------------------------------------------------------------------
# Rule 6: Scheduled task creation
# ---------------------------------------------------------------------------

def rule_scheduled_task(records: list[BaseRecord]) -> list[CorrelatedEvent]:
    """
    Detect scheduled task creation or modification (Events 4698/4702).

    Scheduled task events are always notable regardless of other artefacts.

    Confidence: high
    MITRE: T1053.005
    """
    events: list[CorrelatedEvent] = []

    task_events = [
        r for r in records
        if isinstance(r, EventLogRecord) and r.event_id in (4698, 4702)
    ]

    for task_r in task_events:
        task_name = task_r.event_data.get("TaskName", "unknown")
        subject = task_r.event_data.get("SubjectUserName", "unknown")
        domain = task_r.event_data.get("SubjectDomainName", "")
        actor = f"{domain}\\{subject}" if domain else subject
        action = "created" if task_r.event_id == 4698 else "modified"

        events.append(_make_event(
            records=[task_r],
            tags=["scheduled_task", "persistence"],
            confidence="high",
            notes=[
                f"Scheduled task {action}: {task_name}",
                f"Actor: {actor}",
                f"Timestamp: {task_r.timestamp.isoformat()}",
            ],
            mitre_tags=["T1053.005"],
            rule_id="rule_scheduled_task",
            primary_path=task_r.path,
        ))

    log.debug("rule_scheduled_task: %d findings", len(events))
    return events


# ---------------------------------------------------------------------------
# Rule 7: Executable dropped and run
# ---------------------------------------------------------------------------

def rule_executable_dropped(records: list[BaseRecord]) -> list[CorrelatedEvent]:
    """
    Detect a newly created executable file being run shortly after creation.

    Correlates:
    - MFT record with a recent $FILE_NAME created timestamp
    - Prefetch execution record for the same filename within ±120s

    Confidence: medium (MFT path resolution may be incomplete)
    MITRE: T1204.002
    """
    events: list[CorrelatedEvent] = []

    # Use Prefetch execution timestamps to anchor the "recent" window
    executions = [
        r for r in records
        if r.source == "prefetch" and r.event_type == EventType.EXECUTION
    ]

    mft_records = [
        r for r in records
        if isinstance(r, MFTRecord) and not r.is_directory
    ]

    for exec_r in executions:
        for mft_r in mft_records:
            if mft_r.filename != exec_r.filename:
                continue
            if mft_r.fn_created is None:
                continue
            if not _within(exec_r.timestamp, mft_r.fn_created, _120S):
                continue

            delta = abs((exec_r.timestamp - mft_r.fn_created).total_seconds())
            events.append(_make_event(
                records=[mft_r, exec_r],
                tags=["dropper", "execution", "executable_dropped"],
                confidence="medium",
                notes=[
                    f"Executable created and run within {delta:.1f}s: {exec_r.filename}",
                    f"MFT $FN created: {mft_r.fn_created.isoformat()}",
                    f"Prefetch execution: {exec_r.timestamp.isoformat()}",
                    "Note: MFT path resolution may be incomplete",
                ],
                mitre_tags=["T1204.002"],
                rule_id="rule_executable_dropped",
                primary_path=mft_r.path or exec_r.path,
            ))

    log.debug("rule_executable_dropped: %d findings", len(events))
    return events


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

# All rules in priority order (highest signal first)
ALL_RULES = [
    rule_lolbin_execution,
    rule_log_cleared,
    rule_service_install,
    rule_scheduled_task,
    rule_execution_of_new_file,
    rule_timestomp,
    rule_executable_dropped,
]
