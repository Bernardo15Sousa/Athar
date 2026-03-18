"""
athar.models.evtx
~~~~~~~~~~~~~~~~~
Data model for Windows Event Log (.evtx) artefact records.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from athar.models.base import BaseRecord


@dataclass
class EventLogRecord(BaseRecord):
    """
    Record produced by parsing a Windows Event Log (.evtx) entry.

    Only events matching ``DEFAULT_EVENT_IDS`` (defined in athar.config) are
    extracted. Each record maps to a single event log entry from a single .evtx
    file.

    Attributes
    ----------
    event_id : int
        Windows Event ID (e.g. 4688 = process creation, 4624 = logon success).
    computer : str
        Hostname of the machine that generated the event (from the System header).
    channel : str
        Event log channel name (e.g. "Security", "System", "Microsoft-Windows-PowerShell/Operational").
    provider : str
        Event provider name (e.g. "Microsoft-Windows-Security-Auditing").
    event_data : dict
        Key-value pairs extracted from the EventData XML element.
        Keys and values are both strings, as returned by the XML parser.
        Common keys by event ID:
        - 4688: SubjectUserName, NewProcessName, CommandLine, ParentProcessName
        - 4697 / 7045: ServiceName, ServiceFileName, ServiceType, ServiceStartType
        - 4698 / 4702: TaskName, TaskContent
        - 4624: TargetUserName, LogonType, IpAddress
        - 4104: ScriptBlockText, Path
    """

    event_id: int = 0
    computer: str = ""
    channel: str = ""
    provider: str = ""
    event_data: dict = field(default_factory=dict)
    record_number: int = 0

    def to_dict(self) -> dict:
        """Serialise to plain dictionary, extending BaseRecord.to_dict()."""
        base = super().to_dict()
        base.update({
            "event_id": self.event_id,
            "computer": self.computer,
            "channel": self.channel,
            "provider": self.provider,
            "event_data": self.event_data,
        })
        return base
