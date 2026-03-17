"""
athar.parsers.usn_parser
~~~~~~~~~~~~~~~~~~~~~~~~
Pure-Python parser for the Windows USN Change Journal ($UsnJrnl:$J).

No external libraries required. Implements full USN record v2 binary parsing
from scratch, including sparse region skipping, FILETIME conversion, and
reason flag decoding.

References
----------
- MS-FSCC 2.6: Update Sequence Number (USN) Change Journal
  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b3b67572-ed0b-4e08-b9d5-81d2c54f0478
- USN_RECORD_V2 structure:
  https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2

Usage
-----
    from athar.parsers.usn_parser import parse_usn_journal

    records = parse_usn_journal(Path("/evidence/UsnJrnl_J"))
    for r in records:
        print(r.timestamp, r.filename, r.reason_flags)
"""

from __future__ import annotations

import logging
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from athar.models.base import EventType, basename_from_path, normalise_path
from athar.models.usn import USNRecord

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# USN_RECORD_V2 fixed header size (bytes before FileName field)
_USN_V2_HEADER_SIZE = 60

# FILETIME epoch: 1601-01-01 00:00:00 UTC
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Reason flag bitmask definitions (MS-FSCC 2.6.3)
USN_REASONS: dict[int, str] = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE",
    0x80000000: "CLOSE",
}

# Sparse block size — USN Journal files have large zero-padded regions
_SPARSE_BLOCK_SIZE = 4096

# Maximum sane record length guard (64 KB)
_MAX_RECORD_LENGTH = 65536


# ---------------------------------------------------------------------------
# FILETIME helpers
# ---------------------------------------------------------------------------

def filetime_to_datetime(ft: int) -> datetime:
    """
    Convert a Windows FILETIME value to a UTC-aware datetime.

    FILETIME is a 64-bit value representing the number of 100-nanosecond
    intervals since 1601-01-01 00:00:00 UTC.

    Parameters
    ----------
    ft : int
        Raw FILETIME value from the USN record.

    Returns
    -------
    datetime
        UTC-aware datetime object.

    Examples
    --------
    >>> filetime_to_datetime(0)
    datetime.datetime(1601, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)
    >>> filetime_to_datetime(132000000000000000).year
    2019
    """
    return _FILETIME_EPOCH + timedelta(microseconds=ft // 10)


# ---------------------------------------------------------------------------
# Reason flag decoder
# ---------------------------------------------------------------------------

def parse_reason_flags(flags: int) -> list[str]:
    """
    Decode a USN reason bitmask into a list of human-readable flag names.

    Parameters
    ----------
    flags : int
        Raw reason bitmask from the USN_RECORD_V2.Reason field.

    Returns
    -------
    list[str]
        Sorted list of flag names that are set in the bitmask.

    Examples
    --------
    >>> parse_reason_flags(0x80000100)
    ['CLOSE', 'FILE_CREATE']
    >>> parse_reason_flags(0x00000003)
    ['DATA_EXTEND', 'DATA_OVERWRITE']
    """
    return sorted(
        name for mask, name in USN_REASONS.items() if flags & mask
    )


# ---------------------------------------------------------------------------
# Event type mapping
# ---------------------------------------------------------------------------

def _reason_to_event_type(reason_flags: list[str]) -> str:
    """
    Map a list of USN reason flags to an Athar EventType constant.

    Priority order: DELETE > CREATE > RENAME > MODIFY.

    Parameters
    ----------
    reason_flags : list[str]
        Decoded reason flag names.

    Returns
    -------
    str
        An EventType constant string.
    """
    flags_set = set(reason_flags)
    if "FILE_DELETE" in flags_set:
        return EventType.FILE_DELETE
    if "FILE_CREATE" in flags_set:
        return EventType.FILE_CREATE
    if "RENAME_NEW_NAME" in flags_set:
        return EventType.FILE_RENAME
    if flags_set & {"DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION",
                    "NAMED_DATA_OVERWRITE", "NAMED_DATA_EXTEND"}:
        return EventType.FILE_MODIFY
    return EventType.FILE_MODIFY  # fallback for any other change


# ---------------------------------------------------------------------------
# Binary parsing helpers
# ---------------------------------------------------------------------------

def _is_zero_block(data: bytes) -> bool:
    """Return True if data consists entirely of zero bytes."""
    return not any(data)


def _iter_usn_records(data: bytes) -> Iterator[tuple[int, bytes]]:
    """
    Iterate over raw USN record byte ranges within a binary buffer.

    Handles sparse regions (contiguous zero blocks) by skipping them in
    _SPARSE_BLOCK_SIZE chunks. Yields (offset, record_bytes) tuples.

    Parameters
    ----------
    data : bytes
        Raw content of the $UsnJrnl:$J file.

    Yields
    ------
    tuple[int, bytes]
        (offset, raw_record_bytes) for each valid USN_RECORD_V2 found.
    """
    offset = 0
    size = len(data)

    while offset < size:
        # Need at least 4 bytes to read RecordLength
        if offset + 4 > size:
            break

        # Read RecordLength
        record_length = struct.unpack_from("<I", data, offset)[0]

        if record_length == 0:
            # Sparse / zero region — skip one block
            offset += _SPARSE_BLOCK_SIZE
            continue

        if record_length < _USN_V2_HEADER_SIZE:
            # Corrupt or unrecognised record — advance by 8 bytes and retry
            log.debug("Skipping suspicious record at offset %d: length=%d", offset, record_length)
            offset += 8
            continue

        if record_length > _MAX_RECORD_LENGTH:
            log.debug("Skipping oversized record at offset %d: length=%d", offset, record_length)
            offset += 8
            continue

        if offset + record_length > size:
            log.debug("Record at offset %d extends beyond buffer end — stopping", offset)
            break

        yield offset, data[offset: offset + record_length]
        offset += record_length


# ---------------------------------------------------------------------------
# USN record parser
# ---------------------------------------------------------------------------

def _parse_usn_record(offset: int, raw: bytes) -> USNRecord | None:
    """
    Parse a single USN_RECORD_V2 byte sequence into a USNRecord.

    Parameters
    ----------
    offset : int
        Byte offset within the original file (for error reporting).
    raw : bytes
        Raw record bytes, length == RecordLength.

    Returns
    -------
    USNRecord or None
        Parsed record, or None if the record is malformed.
    """
    try:
        # Unpack fixed header fields
        # <I  RecordLength          (4)  offset 0
        # <H  MajorVersion          (2)  offset 4
        # <H  MinorVersion          (2)  offset 6
        # <Q  FileReferenceNumber   (8)  offset 8
        # <Q  ParentFileReference   (8)  offset 16
        # <q  Usn                   (8)  offset 24
        # <Q  TimeStamp             (8)  offset 32
        # <I  Reason                (4)  offset 40
        # <I  SourceInfo            (4)  offset 44
        # <I  SecurityId            (4)  offset 48
        # <I  FileAttributes        (4)  offset 52
        # <H  FileNameLength        (2)  offset 56
        # <H  FileNameOffset        (2)  offset 58
        (
            record_length,
            major_version,
            _minor_version,
            file_ref,
            parent_ref,
            usn,
            timestamp_ft,
            reason_raw,
            source_info,
            _security_id,
            file_attributes,
            filename_length,
            filename_offset,
        ) = struct.unpack_from("<IHHQQqQIIIIHH", raw, 0)

        if major_version != 2:
            log.debug("Skipping non-v2 USN record at offset %d (version %d)", offset, major_version)
            return None

        # Decode filename (UTF-16LE)
        fn_start = filename_offset
        fn_end = fn_start + filename_length
        if fn_end > len(raw):
            log.warning("Filename extends beyond record at offset %d — skipping", offset)
            return None

        filename = raw[fn_start:fn_end].decode("utf-16-le", errors="replace")

        # Convert timestamp
        timestamp = filetime_to_datetime(timestamp_ft & 0xFFFFFFFFFFFFFFFF)

        # Decode reason flags
        reason_flags = parse_reason_flags(reason_raw)
        event_type = _reason_to_event_type(reason_flags)

        # Build normalised path — USN Journal does not store full paths,
        # only filenames. Correlation engine can enrich from MFT if available.
        normalised_name = normalise_path(filename)

        return USNRecord(
            timestamp=timestamp,
            source="usn",
            event_type=event_type,
            path=normalised_name,
            filename=normalised_name,
            pid=None,
            details={
                "major_version": major_version,
                "source_info": source_info,
            },
            raw={
                "offset": offset,
                "record_length": record_length,
                "reason_raw": f"0x{reason_raw:08X}",
                "file_attributes": f"0x{file_attributes:08X}",
            },
            usn=usn,
            file_reference=file_ref,
            parent_reference=parent_ref,
            reason_flags=reason_flags,
            reason_raw=reason_raw,
            file_attributes=file_attributes,
            source_info=source_info,
        )

    except struct.error as exc:
        log.warning("struct.error parsing USN record at offset %d: %s", offset, exc)
        return None
    except Exception as exc:  # noqa: BLE001
        log.warning("Unexpected error parsing USN record at offset %d: %s", offset, exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_usn_journal(
    path: Path,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[USNRecord]:
    """
    Parse a Windows USN Journal file ($UsnJrnl:$J) into a list of USNRecord objects.

    The file may be a raw binary extracted via forensic tools (e.g. KAPE, FTK)
    or a carved portion. Sparse (zero-padded) regions are skipped automatically.

    Parameters
    ----------
    path : Path
        Path to the $UsnJrnl:$J binary file.
    start : datetime, optional
        If provided, discard records before this UTC-aware datetime.
    end : datetime, optional
        If provided, discard records after this UTC-aware datetime.

    Returns
    -------
    list[USNRecord]
        Parsed records, sorted ascending by timestamp. May be empty if the
        file contains no valid records or all records fall outside the time range.

    Raises
    ------
    FileNotFoundError
        If the specified path does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"USN Journal file not found: {path}")

    log.info("Parsing USN Journal: %s", path)

    try:
        data = path.read_bytes()
    except OSError as exc:
        log.error("Failed to read USN Journal file %s: %s", path, exc)
        return []

    log.debug("USN Journal file size: %d bytes", len(data))

    records: list[USNRecord] = []
    skipped = 0

    for offset, raw in _iter_usn_records(data):
        record = _parse_usn_record(offset, raw)
        if record is None:
            skipped += 1
            continue

        # Apply time range filter
        if start and record.timestamp < start:
            continue
        if end and record.timestamp > end:
            continue

        records.append(record)

    log.info(
        "USN Journal parse complete: %d records parsed, %d skipped from %s",
        len(records),
        skipped,
        path.name,
    )

    records.sort(key=lambda r: r.timestamp)
    return records
