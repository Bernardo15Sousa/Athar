"""
tests.test_usn
~~~~~~~~~~~~~~
Unit tests for athar.parsers.usn_parser.

All test fixtures are generated synthetically in-memory — no external binary
files required. The fixture builder constructs valid USN_RECORD_V2 binary
structures that match the MS-FSCC specification exactly.
"""

from __future__ import annotations

import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from athar.models.base import EventType
from athar.parsers.usn_parser import (
    USN_REASONS,
    filetime_to_datetime,
    parse_reason_flags,
    parse_usn_journal,
    _parse_usn_record,
    _reason_to_event_type,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def datetime_to_filetime(dt: datetime) -> int:
    """Convert UTC-aware datetime to Windows FILETIME integer."""
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = dt - epoch
    return int(delta.total_seconds() * 10_000_000)


def build_usn_record_v2(
    filename: str,
    timestamp: datetime,
    reason: int = 0x00000100,  # FILE_CREATE
    file_ref: int = 0x0001000000000042,
    parent_ref: int = 0x0001000000000005,
    usn: int = 1024,
    file_attributes: int = 0x00000020,  # ARCHIVE
    source_info: int = 0,
    security_id: int = 0,
) -> bytes:
    """
    Build a valid USN_RECORD_V2 binary payload.

    Parameters
    ----------
    filename : str
        Filename to embed (UTF-16LE encoded).
    timestamp : datetime
        UTC-aware datetime to embed as FILETIME.
    reason : int
        Reason bitmask.
    file_ref, parent_ref : int
        64-bit file reference numbers.
    usn : int
        USN offset value.
    file_attributes, source_info, security_id : int
        Attribute fields.

    Returns
    -------
    bytes
        Packed USN_RECORD_V2 record.
    """
    encoded_name = filename.encode("utf-16-le")
    filename_length = len(encoded_name)
    filename_offset = 60  # fixed header is 60 bytes
    record_length = filename_offset + filename_length

    # Align to 8-byte boundary
    if record_length % 8:
        record_length += 8 - (record_length % 8)

    ft = datetime_to_filetime(timestamp)

    header = struct.pack(
        "<IHHQQqQIIIIHH",
        record_length,       # RecordLength
        2,                   # MajorVersion
        0,                   # MinorVersion
        file_ref,            # FileReferenceNumber
        parent_ref,          # ParentFileReferenceNumber
        usn,                 # Usn
        ft,                  # TimeStamp (FILETIME)
        reason,              # Reason
        source_info,         # SourceInfo
        security_id,         # SecurityId
        file_attributes,     # FileAttributes
        filename_length,     # FileNameLength
        filename_offset,     # FileNameOffset
    )

    payload = header + encoded_name
    # Pad to record_length
    payload += b"\x00" * (record_length - len(payload))
    return payload


def build_usn_journal_file(records: list[bytes], leading_zeros: int = 0) -> bytes:
    """
    Assemble multiple USN records into a single binary buffer,
    optionally prepended with a sparse zero region.
    """
    return b"\x00" * leading_zeros + b"".join(records)


# ---------------------------------------------------------------------------
# filetime_to_datetime
# ---------------------------------------------------------------------------

class TestFiletimeConversion:
    def test_epoch(self):
        dt = filetime_to_datetime(0)
        assert dt == datetime(1601, 1, 1, tzinfo=timezone.utc)

    def test_known_value(self):
        # 2024-01-15 12:00:00 UTC
        dt = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        ft = datetime_to_filetime(dt)
        result = filetime_to_datetime(ft)
        # Allow 1 microsecond rounding tolerance
        assert abs((result - dt).total_seconds()) < 0.000002

    def test_returns_utc_aware(self):
        dt = filetime_to_datetime(132000000000000000)
        assert dt.tzinfo is not None
        assert dt.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# parse_reason_flags
# ---------------------------------------------------------------------------

class TestParseReasonFlags:
    def test_file_create(self):
        flags = parse_reason_flags(0x00000100)
        assert "FILE_CREATE" in flags

    def test_file_delete(self):
        flags = parse_reason_flags(0x00000200)
        assert "FILE_DELETE" in flags

    def test_multiple_flags(self):
        # FILE_CREATE | CLOSE
        flags = parse_reason_flags(0x80000100)
        assert "FILE_CREATE" in flags
        assert "CLOSE" in flags

    def test_zero_returns_empty(self):
        assert parse_reason_flags(0) == []

    def test_sorted_output(self):
        flags = parse_reason_flags(0x80000300)
        assert flags == sorted(flags)

    def test_all_known_flags_decodable(self):
        all_flags = 0
        for mask in USN_REASONS:
            all_flags |= mask
        decoded = parse_reason_flags(all_flags)
        assert len(decoded) == len(USN_REASONS)

    def test_unknown_bits_ignored(self):
        # Bit 3 is not in USN_REASONS
        flags = parse_reason_flags(0x00000008)
        assert flags == []


# ---------------------------------------------------------------------------
# _reason_to_event_type
# ---------------------------------------------------------------------------

class TestReasonToEventType:
    def test_file_create(self):
        assert _reason_to_event_type(["FILE_CREATE"]) == EventType.FILE_CREATE

    def test_file_delete(self):
        assert _reason_to_event_type(["FILE_DELETE"]) == EventType.FILE_DELETE

    def test_rename(self):
        assert _reason_to_event_type(["RENAME_NEW_NAME"]) == EventType.FILE_RENAME

    def test_data_extend(self):
        assert _reason_to_event_type(["DATA_EXTEND"]) == EventType.FILE_MODIFY

    def test_delete_takes_priority_over_create(self):
        # Edge case: both flags set
        assert _reason_to_event_type(["FILE_DELETE", "FILE_CREATE"]) == EventType.FILE_DELETE

    def test_close_only_falls_back_to_modify(self):
        assert _reason_to_event_type(["CLOSE"]) == EventType.FILE_MODIFY


# ---------------------------------------------------------------------------
# _parse_usn_record
# ---------------------------------------------------------------------------

class TestParseUsnRecord:
    def test_basic_record(self):
        ts = datetime(2024, 3, 15, 10, 30, 0, tzinfo=timezone.utc)
        raw = build_usn_record_v2("malware.exe", ts, reason=0x00000100)
        record = _parse_usn_record(0, raw)

        assert record is not None
        assert record.filename == "MALWARE.EXE"
        assert record.event_type == EventType.FILE_CREATE
        assert "FILE_CREATE" in record.reason_flags
        assert record.source == "usn"
        assert abs((record.timestamp - ts).total_seconds()) < 0.000002

    def test_timestamp_is_utc_aware(self):
        ts = datetime(2024, 3, 15, 10, 30, 0, tzinfo=timezone.utc)
        raw = build_usn_record_v2("test.txt", ts)
        record = _parse_usn_record(0, raw)
        assert record is not None
        assert record.timestamp.tzinfo is not None

    def test_file_reference_parsed(self):
        raw = build_usn_record_v2(
            "test.exe",
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            file_ref=0x0001000000000042,
        )
        record = _parse_usn_record(0, raw)
        assert record is not None
        assert record.mft_entry == 0x42
        assert record.mft_sequence == 1

    def test_delete_reason(self):
        ts = datetime(2024, 3, 15, tzinfo=timezone.utc)
        raw = build_usn_record_v2("dropped.exe", ts, reason=0x00000200)  # FILE_DELETE
        record = _parse_usn_record(0, raw)
        assert record is not None
        assert record.event_type == EventType.FILE_DELETE

    def test_rename_reason(self):
        ts = datetime(2024, 3, 15, tzinfo=timezone.utc)
        raw = build_usn_record_v2("new_name.dll", ts, reason=0x00002000)  # RENAME_NEW_NAME
        record = _parse_usn_record(0, raw)
        assert record is not None
        assert record.event_type == EventType.FILE_RENAME

    def test_non_v2_record_returns_none(self):
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        raw = bytearray(build_usn_record_v2("test.exe", ts))
        # Overwrite MajorVersion (offset 4) with 3
        struct.pack_into("<H", raw, 4, 3)
        record = _parse_usn_record(0, bytes(raw))
        assert record is None

    def test_truncated_record_returns_none(self):
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        raw = build_usn_record_v2("test.exe", ts)
        # Truncate to 30 bytes — below header size
        record = _parse_usn_record(0, raw[:30])
        assert record is None

    def test_unicode_filename(self):
        ts = datetime(2024, 3, 15, tzinfo=timezone.utc)
        raw = build_usn_record_v2("документ.docx", ts)
        record = _parse_usn_record(0, raw)
        assert record is not None
        assert "DOCX" in record.filename

    def test_path_is_uppercase(self):
        ts = datetime(2024, 3, 15, tzinfo=timezone.utc)
        raw = build_usn_record_v2("MixedCase.exe", ts)
        record = _parse_usn_record(0, raw)
        assert record is not None
        assert record.filename == record.filename.upper()

    def test_close_flag_alongside_create(self):
        ts = datetime(2024, 3, 15, tzinfo=timezone.utc)
        raw = build_usn_record_v2("setup.exe", ts, reason=0x80000100)  # FILE_CREATE | CLOSE
        record = _parse_usn_record(0, raw)
        assert record is not None
        assert "FILE_CREATE" in record.reason_flags
        assert "CLOSE" in record.reason_flags


# ---------------------------------------------------------------------------
# parse_usn_journal (end-to-end)
# ---------------------------------------------------------------------------

class TestParseUsnJournal:
    def _write_journal(self, content: bytes) -> Path:
        """Write binary content to a temp file and return its path."""
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".$J")
        tmp.write(content)
        tmp.close()
        return Path(tmp.name)

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_usn_journal(Path("/nonexistent/path/$J"))

    def test_empty_file_returns_empty_list(self):
        path = self._write_journal(b"")
        records = parse_usn_journal(path)
        assert records == []

    def test_all_zeros_returns_empty_list(self):
        path = self._write_journal(b"\x00" * 8192)
        records = parse_usn_journal(path)
        assert records == []

    def test_single_record(self):
        ts = datetime(2024, 3, 15, 10, 30, 0, tzinfo=timezone.utc)
        raw_record = build_usn_record_v2("cmd.exe", ts)
        path = self._write_journal(raw_record)
        records = parse_usn_journal(path)
        assert len(records) == 1
        assert records[0].filename == "CMD.EXE"

    def test_multiple_records_sorted_by_timestamp(self):
        ts1 = datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2024, 3, 15, 9, 0, 0, tzinfo=timezone.utc)   # earlier
        ts3 = datetime(2024, 3, 15, 11, 0, 0, tzinfo=timezone.utc)  # latest

        content = build_usn_journal_file([
            build_usn_record_v2("a.exe", ts1),
            build_usn_record_v2("b.exe", ts2),
            build_usn_record_v2("c.exe", ts3),
        ])
        path = self._write_journal(content)
        records = parse_usn_journal(path)

        assert len(records) == 3
        timestamps = [r.timestamp for r in records]
        assert timestamps == sorted(timestamps)

    def test_leading_sparse_zeros_skipped(self):
        ts = datetime(2024, 3, 15, 10, 30, 0, tzinfo=timezone.utc)
        raw_record = build_usn_record_v2("payload.exe", ts)
        # 8 KB of zeros before the real record
        content = b"\x00" * 8192 + raw_record
        path = self._write_journal(content)
        records = parse_usn_journal(path)
        assert len(records) == 1
        assert records[0].filename == "PAYLOAD.EXE"

    def test_time_range_filter_start(self):
        ts_early = datetime(2024, 3, 15, 8, 0, 0, tzinfo=timezone.utc)
        ts_late = datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
        content = build_usn_journal_file([
            build_usn_record_v2("early.exe", ts_early),
            build_usn_record_v2("late.exe", ts_late),
        ])
        path = self._write_journal(content)
        filter_start = datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        records = parse_usn_journal(path, start=filter_start)
        assert len(records) == 1
        assert records[0].filename == "LATE.EXE"

    def test_time_range_filter_end(self):
        ts_early = datetime(2024, 3, 15, 8, 0, 0, tzinfo=timezone.utc)
        ts_late = datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
        content = build_usn_journal_file([
            build_usn_record_v2("early.exe", ts_early),
            build_usn_record_v2("late.exe", ts_late),
        ])
        path = self._write_journal(content)
        filter_end = datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        records = parse_usn_journal(path, end=filter_end)
        assert len(records) == 1
        assert records[0].filename == "EARLY.EXE"

    def test_lolbin_detected_in_filename(self):
        ts = datetime(2024, 3, 15, tzinfo=timezone.utc)
        content = build_usn_record_v2("powershell.exe", ts, reason=0x80000100)
        path = self._write_journal(content)
        records = parse_usn_journal(path)
        assert len(records) == 1
        assert records[0].filename == "POWERSHELL.EXE"

    def test_reason_raw_preserved(self):
        ts = datetime(2024, 3, 15, tzinfo=timezone.utc)
        raw_record = build_usn_record_v2("test.txt", ts, reason=0x00000300)
        path = self._write_journal(raw_record)
        records = parse_usn_journal(path)
        assert len(records) == 1
        assert records[0].reason_raw == 0x00000300

    def test_returns_list_type(self):
        path = self._write_journal(b"\x00" * 512)
        result = parse_usn_journal(path)
        assert isinstance(result, list)
