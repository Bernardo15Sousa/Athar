"""
athar.parsers.evtx_parser
~~~~~~~~~~~~~~~~~~~~~~~~~
Parser for Windows Event Log files (.evtx).

Wraps python-evtx to extract targeted Event IDs relevant to incident response,
normalises all fields to Athar data models, and extracts path information from
EventData where applicable.

Supported Event IDs (configurable via event_ids parameter):
    4624  Logon success
    4625  Logon failure
    4648  Explicit credentials logon
    4688  Process creation
    4697  Service installed (Security log)
    4698  Scheduled task created
    4702  Scheduled task modified
    4720  User account created
    4726  User account deleted
    4732  Member added to security group
    4733  Member removed from security group
    7045  New service installed (System log)
    1102  Audit log cleared
    4104  PowerShell ScriptBlock logged

Usage
-----
    from athar.parsers.evtx_parser import parse_evtx_directory

    records = parse_evtx_directory(Path("/evidence/evtx/"))
    for r in records:
        print(r.event_id, r.timestamp, r.path)
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# Use defusedxml to prevent XXE and billion-laughs attacks when parsing
# untrusted EVTX XML. Falls back to stdlib with a warning if not installed.
try:
    import defusedxml.ElementTree as _safe_ET  # type: ignore
    _parse_xml_string = _safe_ET.fromstring
except ImportError:  # pragma: no cover
    log_startup = logging.getLogger(__name__)
    log_startup.warning(
        "defusedxml is not installed. XML parsing may be vulnerable to XXE "
        "attacks. Install it with: pip install defusedxml"
    )
    _parse_xml_string = ET.fromstring
from pathlib import Path
from typing import Optional

from athar.models.base import EventType, normalise_path, basename_from_path
from athar.models.evtx import EventLogRecord

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# XML namespace used in EVTX records
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Default Event IDs to extract: (event_type, human_label)
DEFAULT_EVENT_IDS: dict[int, tuple[str, str]] = {
    4624: (EventType.LOGON,          "Logon success"),
    4625: (EventType.LOGON_FAIL,     "Logon failure"),
    4648: (EventType.LOGON,          "Explicit credentials logon"),
    4688: (EventType.PROCESS_CREATE, "Process creation"),
    4697: (EventType.SERVICE_INSTALL,"Service installed"),
    4698: (EventType.TASK_CREATE,    "Scheduled task created"),
    4702: (EventType.TASK_CREATE,    "Scheduled task modified"),
    4720: (EventType.USER_CREATE,    "User account created"),
    4726: (EventType.USER_CREATE,    "User account deleted"),
    4732: (EventType.GROUP_CHANGE,   "Member added to group"),
    4733: (EventType.GROUP_CHANGE,   "Member removed from group"),
    7045: (EventType.SERVICE_INSTALL,"New service installed"),
    1102: (EventType.LOG_CLEARED,    "Audit log cleared"),
    4104: (EventType.SCRIPT_BLOCK,   "PowerShell ScriptBlock"),
}

# EventData field names that contain executable/file paths, keyed by Event ID
_PATH_FIELDS: dict[int, list[str]] = {
    4688: ["NewProcessName", "ParentProcessName"],
    4697: ["ServiceFileName"],
    4698: ["TaskName"],
    4702: ["TaskName"],
    7045: ["ImagePath"],
    4104: [],
}


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def _ns(tag: str) -> str:
    """Return a namespace-qualified XML tag."""
    return f"{{{_NS}}}{tag}"


def _parse_event_xml(xml_string: str) -> Optional[ET.Element]:
    """
    Parse an EVTX event XML string into an ElementTree Element.

    Returns None on parse failure.
    """
    try:
        return _parse_xml_string(xml_string)
    except ET.ParseError as exc:
        log.debug("XML parse error: %s", exc)
        return None


def _extract_system_fields(system: ET.Element) -> dict:
    """
    Extract System-level fields from an EVTX event's <System> element.

    Returns a dict with keys: event_id, computer, channel, provider,
    time_created, record_number.
    """
    result: dict = {}

    # Provider name
    provider = system.find(_ns("Provider"))
    result["provider"] = provider.get("Name", "") if provider is not None else ""

    # Event ID — may be nested as <EventID Qualifiers="...">4688</EventID>
    event_id_el = system.find(_ns("EventID"))
    if event_id_el is not None and event_id_el.text:
        try:
            result["event_id"] = int(event_id_el.text.strip())
        except ValueError:
            result["event_id"] = 0
    else:
        result["event_id"] = 0

    # TimeCreated
    time_created = system.find(_ns("TimeCreated"))
    if time_created is not None:
        result["time_created_str"] = time_created.get("SystemTime", "")
    else:
        result["time_created_str"] = ""

    # Computer
    computer = system.find(_ns("Computer"))
    result["computer"] = computer.text.strip() if computer is not None and computer.text else ""

    # Channel
    channel = system.find(_ns("Channel"))
    result["channel"] = channel.text.strip() if channel is not None and channel.text else ""

    # EventRecordID
    record_id = system.find(_ns("EventRecordID"))
    if record_id is not None and record_id.text:
        try:
            result["record_number"] = int(record_id.text.strip())
        except ValueError:
            result["record_number"] = 0
    else:
        result["record_number"] = 0

    return result


def _parse_time_created(time_str: str) -> Optional[datetime]:
    """
    Parse an EVTX SystemTime string to a UTC-aware datetime.

    Handles formats:
        2024-03-15T10:30:00.000000000Z
        2024-03-15T10:30:00.000000Z
        2024-03-15T10:30:00Z
    """
    if not time_str:
        return None
    try:
        # Trim nanoseconds to microseconds (Python datetime supports up to µs)
        # Remove trailing Z and handle variable precision
        clean = time_str.rstrip("Z")
        if "." in clean:
            base, frac = clean.split(".", 1)
            # Truncate fractional seconds to 6 digits
            frac = frac[:6].ljust(6, "0")
            clean = f"{base}.{frac}"
        else:
            clean = clean

        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, OverflowError) as exc:
        log.debug("Failed to parse timestamp %r: %s", time_str, exc)
        return None


def _extract_event_data(event_data_el: Optional[ET.Element]) -> dict[str, str]:
    """
    Extract key-value pairs from an EVTX <EventData> or <UserData> element.

    Handles both named Data elements (<Data Name="Key">Value</Data>)
    and positional elements.
    """
    if event_data_el is None:
        return {}

    result: dict[str, str] = {}
    for i, child in enumerate(event_data_el):
        name = child.get("Name")
        value = child.text or ""
        if name:
            result[name] = value.strip()
        else:
            # Positional fallback
            result[f"Data_{i}"] = value.strip()
    return result


def _extract_path_from_event(event_id: int, event_data: dict[str, str]) -> str:
    """
    Extract the most relevant file/process path from EventData fields.

    Returns a normalised Windows path string, or empty string if not found.
    """
    fields = _PATH_FIELDS.get(event_id, [])
    for field_name in fields:
        value = event_data.get(field_name, "").strip()
        if value and value not in ("-", "N/A", ""):
            return normalise_path(value)
    return ""


def _extract_pid(event_id: int, event_data: dict[str, str]) -> Optional[int]:
    """Extract PID from EventData where applicable."""
    if event_id == 4688:
        pid_hex = event_data.get("NewProcessId", "")
        if pid_hex:
            try:
                return int(pid_hex, 16)
            except ValueError:
                try:
                    return int(pid_hex)
                except ValueError:
                    pass
    return None


# ---------------------------------------------------------------------------
# Single file parser
# ---------------------------------------------------------------------------

def parse_evtx_file(
    path: Path,
    event_ids: Optional[dict[int, tuple[str, str]]] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[EventLogRecord]:
    """
    Parse a single .evtx file and return matching EventLogRecord objects.

    Parameters
    ----------
    path : Path
        Path to the .evtx file.
    event_ids : dict, optional
        Mapping of {event_id: (event_type, label)} to extract.
        Defaults to DEFAULT_EVENT_IDS.
    start : datetime, optional
        Discard records before this UTC-aware datetime.
    end : datetime, optional
        Discard records after this UTC-aware datetime.

    Returns
    -------
    list[EventLogRecord]
        Parsed records for matching Event IDs within the time range.
    """
    if event_ids is None:
        event_ids = DEFAULT_EVENT_IDS

    records: list[EventLogRecord] = []

    try:
        import Evtx.Evtx as evtx  # python-evtx
    except ImportError:
        log.error(
            "python-evtx is not installed. Install it with: pip install python-evtx"
        )
        return []

    try:
        with evtx.Evtx(str(path)) as log_file:
            for record in log_file.records():
                try:
                    xml_str = record.xml()
                except (OSError, ValueError, RuntimeError, UnicodeDecodeError) as exc:
                    log.debug("Failed to get XML for record in %s: %s", path.name, exc)
                    continue

                root = _parse_event_xml(xml_str)
                if root is None:
                    continue

                system_el = root.find(_ns("System"))
                if system_el is None:
                    continue

                sys_fields = _extract_system_fields(system_el)
                event_id = sys_fields.get("event_id", 0)

                if event_id not in event_ids:
                    continue

                timestamp = _parse_time_created(sys_fields.get("time_created_str", ""))
                if timestamp is None:
                    log.debug("Skipping record with unparseable timestamp in %s", path.name)
                    continue

                # Apply time range filter
                if start and timestamp < start:
                    continue
                if end and timestamp > end:
                    continue

                # Extract EventData
                event_data_el = root.find(_ns("EventData"))
                if event_data_el is None:
                    event_data_el = root.find(_ns("UserData"))
                event_data = _extract_event_data(event_data_el)

                event_type, label = event_ids[event_id]
                path_value = _extract_path_from_event(event_id, event_data)
                pid = _extract_pid(event_id, event_data)

                evtx_record = EventLogRecord(
                    timestamp=timestamp,
                    source="evtx",
                    event_type=event_type,
                    path=path_value,
                    filename=basename_from_path(path_value) if path_value else "",
                    pid=pid,
                    details={"label": label, "log_file": path.name},
                    event_id=event_id,
                    computer=sys_fields.get("computer", ""),
                    channel=sys_fields.get("channel", ""),
                    provider=sys_fields.get("provider", ""),
                    event_data=event_data,
                    record_number=sys_fields.get("record_number", 0),
                )
                records.append(evtx_record)

    except FileNotFoundError:
        raise
    except (OSError, ValueError, RuntimeError, UnicodeDecodeError) as exc:
        log.warning("Failed to parse EVTX file %s: %s", path, exc)

    return records


# ---------------------------------------------------------------------------
# Directory parser
# ---------------------------------------------------------------------------

def parse_evtx_directory(
    directory: Path,
    event_ids: Optional[dict[int, tuple[str, str]]] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[EventLogRecord]:
    """
    Parse all .evtx files in a directory and return combined EventLogRecord list.

    Files are processed in sorted order. Records from all files are merged into
    a single list sorted ascending by timestamp.

    Parameters
    ----------
    directory : Path
        Directory containing .evtx files. Searched non-recursively.
    event_ids : dict, optional
        Event IDs to extract. Defaults to DEFAULT_EVENT_IDS.
    start : datetime, optional
        Discard records before this UTC-aware datetime.
    end : datetime, optional
        Discard records after this UTC-aware datetime.

    Returns
    -------
    list[EventLogRecord]
        All matching records from all .evtx files, sorted by timestamp.

    Raises
    ------
    NotADirectoryError
        If the specified path is not a directory.
    """
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    evtx_files = sorted(directory.glob("*.evtx"))

    if not evtx_files:
        log.warning("No .evtx files found in %s", directory)
        return []

    log.info("Found %d .evtx file(s) in %s", len(evtx_files), directory)

    all_records: list[EventLogRecord] = []
    for evtx_path in evtx_files:
        log.info("Parsing EVTX: %s", evtx_path.name)
        file_records = parse_evtx_file(evtx_path, event_ids, start, end)
        log.info("  → %d records from %s", len(file_records), evtx_path.name)
        all_records.extend(file_records)

    all_records.sort(key=lambda r: r.timestamp)
    log.info("EVTX parse complete: %d total records from %d files", len(all_records), len(evtx_files))
    return all_records
