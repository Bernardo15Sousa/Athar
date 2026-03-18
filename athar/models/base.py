"""
athar.models.base
~~~~~~~~~~~~~~~~~
Core data structures shared across all artefact parsers and the correlation engine.

All timestamps are UTC-aware datetime objects.
All paths are uppercase, backslash-normalised Windows paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class EventType:
    """
    Canonical event type constants used across all artefact sources.
    Always use these constants — never raw strings.
    """

    EXECUTION = "execution"
    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    FILE_RENAME = "file_rename"
    FILE_MODIFY = "file_modify"
    PROCESS_CREATE = "process_create"
    LOGON = "logon"
    LOGON_FAIL = "logon_failure"
    SERVICE_INSTALL = "service_install"
    TASK_CREATE = "task_create"
    LOG_CLEARED = "log_cleared"
    SCRIPT_BLOCK = "script_block"
    USER_CREATE = "user_create"
    GROUP_CHANGE = "group_change"

    # All valid values — used for validation
    _ALL: set[str] = {
        "execution", "file_create", "file_delete", "file_rename", "file_modify",
        "process_create", "logon", "logon_failure", "service_install",
        "task_create", "log_cleared", "script_block", "user_create", "group_change",
    }

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Return True if value is a known EventType constant."""
        return value in cls._ALL


def normalise_path(path: str) -> str:
    """
    Normalise a Windows path to uppercase with backslashes.
    Applied at parse time on all path fields.

    Examples
    --------
    >>> normalise_path("c:/windows/system32/cmd.exe")
    'C:\\\\WINDOWS\\\\SYSTEM32\\\\CMD.EXE'
    >>> normalise_path("\\\\Device\\\\HarddiskVolume3\\\\Windows\\\\explorer.exe")
    '\\\\\\\\DEVICE\\\\HARDDISKVOLUME3\\\\WINDOWS\\\\EXPLORER.EXE'
    """
    if not path:
        return ""
    return path.replace("/", "\\").upper()


def basename_from_path(path: str) -> str:
    """
    Extract the filename component from a normalised Windows path.

    Examples
    --------
    >>> basename_from_path("C:\\\\WINDOWS\\\\SYSTEM32\\\\CMD.EXE")
    'CMD.EXE'
    """
    if not path:
        return ""
    # os.path.basename handles backslash on all platforms
    return os.path.basename(path.replace("\\", os.sep)).upper()


@dataclass
class BaseRecord:
    """
    Base forensic artefact record.

    Every artefact parser produces records that are either BaseRecord instances
    or subclasses thereof. The correlation engine operates on BaseRecord fields.

    Attributes
    ----------
    timestamp : datetime
        UTC-aware datetime of the event.
    source : str
        Artefact source identifier: "prefetch" | "mft" | "usn" | "evtx".
    event_type : str
        Event classification — use EventType constants.
    path : str
        Full Windows path, uppercase, backslash-normalised.
    filename : str
        Basename of path, uppercase.
    pid : int, optional
        Process ID if available.
    details : dict
        Source-specific supplementary fields.
    raw : dict, optional
        Original parsed dict before normalisation. Preserved for debugging.
    """

    timestamp: datetime
    source: str
    event_type: str
    path: str
    filename: str
    pid: Optional[int] = None
    details: dict = field(default_factory=dict)
    raw: Optional[dict] = None

    def __post_init__(self) -> None:
        # Enforce path normalisation
        self.path = normalise_path(self.path)
        if not self.filename:
            self.filename = basename_from_path(self.path)
        else:
            self.filename = self.filename.upper()

        # Enforce UTC awareness
        if self.timestamp.tzinfo is None:
            raise ValueError(
                f"BaseRecord.timestamp must be timezone-aware (UTC). "
                f"Got naive datetime: {self.timestamp!r}"
            )

    def to_dict(self) -> dict:
        """Serialise record to a plain dictionary for JSON/CSV export."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "path": self.path,
            "filename": self.filename,
            "pid": self.pid,
            "details": self.details,
        }


@dataclass
class CorrelatedEvent:
    """
    A correlated forensic event produced by the correlation engine.

    Represents a meaningful finding derived from one or more BaseRecord instances
    that share temporal and/or path proximity and match a correlation rule.

    Attributes
    ----------
    window_start : datetime
        Earliest timestamp among contributing records.
    window_end : datetime
        Latest timestamp among contributing records.
    primary_path : str
        The main file path this event concerns.
    primary_filename : str
        Basename of primary_path.
    records : list[BaseRecord]
        All artefact records that contributed to this event.
    tags : list[str]
        Semantic tags e.g. ["lolbin_execution", "execution"].
    confidence : str
        Analyst confidence level: "high" | "medium" | "low".
    notes : list[str]
        Human-readable analyst notes explaining the correlation.
    mitre_tags : list[str]
        MITRE ATT&CK technique IDs e.g. ["T1218.011"].
    rule_id : str
        Identifier of the rule that produced this event.
    """

    window_start: datetime
    window_end: datetime
    primary_path: str
    primary_filename: str
    records: list[BaseRecord]
    tags: list[str]
    confidence: str
    notes: list[str]
    mitre_tags: list[str]
    rule_id: str = ""

    VALID_CONFIDENCE = {"high", "medium", "low"}

    def __post_init__(self) -> None:
        if self.confidence not in self.VALID_CONFIDENCE:
            raise ValueError(
                f"CorrelatedEvent.confidence must be one of {self.VALID_CONFIDENCE}, "
                f"got {self.confidence!r}"
            )
        self.primary_path = normalise_path(self.primary_path)
        if not self.primary_filename:
            self.primary_filename = basename_from_path(self.primary_path)

    @property
    def source_set(self) -> set[str]:
        """Return the set of artefact sources contributing to this event."""
        return {r.source for r in self.records}

    def to_dict(self) -> dict:
        """Serialise to plain dictionary for JSON export."""
        return {
            "rule_id": self.rule_id,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "primary_path": self.primary_path,
            "primary_filename": self.primary_filename,
            "tags": self.tags,
            "confidence": self.confidence,
            "mitre_tags": self.mitre_tags,
            "notes": self.notes,
            "source_set": sorted(self.source_set),
            "record_count": len(self.records),
            "records": [r.to_dict() for r in self.records],
        }
