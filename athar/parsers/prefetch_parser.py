"""
athar.parsers.prefetch_parser
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Parser for Windows Prefetch (.pf) files.

Attempts to use python-libscca if available. Falls back to a pure-Python
implementation that covers the most common formats (v17, v23, v26, v30).

Win10+ prefetch files use MAM (Xpress Huffman) compression. If the python-libscca
library is not available and the file is compressed, a warning is logged and the
file is skipped gracefully rather than crashing.

Prefetch file versions:
    17  Windows XP / 2003
    23  Windows Vista / 7
    26  Windows 8 / 8.1
    30  Windows 10+ (may be MAM-compressed)

One PrefetchRecord is emitted per execution timestamp — a .pf file with 3
recorded run times produces 3 records, all sharing executable metadata.

Usage
-----
    from athar.parsers.prefetch_parser import parse_prefetch_directory

    records = parse_prefetch_directory(Path("/evidence/Prefetch/"))
    for r in records:
        print(r.executable, r.timestamp, r.run_count)
"""

from __future__ import annotations

import logging
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from athar.models.base import EventType, normalise_path
from athar.models.prefetch import PrefetchRecord

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Prefetch file signature: "SCCA"
_SCCA_SIGNATURE = b"SCCA"

# MAM compression signature (Win10+)
_MAM_SIGNATURE = b"\x4d\x41\x4d\x04"

# FILETIME epoch
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Regex to extract hash from .pf filename: CMD.EXE-AB1234CD.pf
_PF_HASH_RE = re.compile(r"^(.+)-([0-9A-Fa-f]{8})\.pf$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _filetime_to_datetime(ft: int) -> Optional[datetime]:
    """Convert Windows FILETIME to UTC-aware datetime. Returns None if ft is 0."""
    if ft == 0:
        return None
    from datetime import timedelta
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


def _decode_utf16(data: bytes) -> str:
    """Decode a null-terminated UTF-16LE string from bytes."""
    try:
        # Find double-null terminator
        idx = 0
        while idx < len(data) - 1:
            if data[idx] == 0 and data[idx + 1] == 0:
                break
            idx += 2
        return data[:idx].decode("utf-16-le", errors="replace")
    except Exception:
        return ""


def _parse_pf_filename(filename: str) -> tuple[str, str]:
    """
    Extract executable name and hash from a .pf filename.

    Returns (executable_name, hash_string).
    E.g. "CMD.EXE-AB1234CD.pf" → ("CMD.EXE", "AB1234CD")
    """
    m = _PF_HASH_RE.match(filename)
    if m:
        return m.group(1).upper(), m.group(2).upper()
    # Fallback
    name = filename.upper().replace(".PF", "")
    return name, ""


def _is_mam_compressed(data: bytes) -> bool:
    """Return True if the file uses MAM (Xpress Huffman) compression."""
    return len(data) >= 4 and data[:4] == _MAM_SIGNATURE


def _decompress_mam(data: bytes) -> Optional[bytes]:
    """
    Attempt to decompress MAM-compressed prefetch data.

    Requires the 'mam' package or Windows-specific ctypes calls.
    Returns None if decompression is not available on this platform.
    """
    try:
        # Try the 'mam' Python package if installed
        import mam  # type: ignore
        return mam.decompress(data)
    except ImportError:
        pass

    try:
        # Windows-only: use RtlDecompressBufferEx via ctypes
        import ctypes
        import ctypes.wintypes as wt

        ntdll = ctypes.WinDLL("ntdll.dll")

        # Read uncompressed size from header (offset 4, DWORD)
        uncompressed_size = struct.unpack_from("<I", data, 4)[0]
        uncompressed = (ctypes.c_ubyte * uncompressed_size)()
        final_size = ctypes.c_ulong(0)
        workspace = (ctypes.c_ubyte * (uncompressed_size * 2))()

        status = ntdll.RtlDecompressBufferEx(
            4,                          # COMPRESSION_FORMAT_XPRESS_HUFF
            ctypes.byref(uncompressed),
            uncompressed_size,
            ctypes.cast(data[8:], ctypes.POINTER(ctypes.c_ubyte)),
            len(data) - 8,
            ctypes.byref(final_size),
            ctypes.byref(workspace),
        )
        if status == 0:
            return bytes(uncompressed[: final_size.value])
    except Exception:
        pass

    return None


# ---------------------------------------------------------------------------
# Version-specific parsers
# ---------------------------------------------------------------------------

def _parse_run_times_v17_v23(data: bytes, version: int) -> list[datetime]:
    """
    Parse last run time from Prefetch v17 (XP) and v23 (Vista/7).
    These versions store a single run time at offset 0x78.
    """
    try:
        ft = struct.unpack_from("<Q", data, 0x78)[0]
        dt = _filetime_to_datetime(ft)
        return [dt] if dt else []
    except struct.error:
        return []


def _parse_run_times_v26_v30(data: bytes) -> list[datetime]:
    """
    Parse up to 8 run times from Prefetch v26 (Win8) and v30 (Win10+).
    Run times are stored at offset 0x80 as 8 consecutive QWORDs.
    """
    times: list[datetime] = []
    try:
        for i in range(8):
            offset = 0x80 + (i * 8)
            ft = struct.unpack_from("<Q", data, offset)[0]
            dt = _filetime_to_datetime(ft)
            if dt:
                times.append(dt)
    except struct.error:
        pass
    return times


def _parse_run_count(data: bytes, version: int) -> int:
    """Extract run count from appropriate offset per version."""
    try:
        if version in (17, 23):
            return struct.unpack_from("<I", data, 0x90)[0]
        elif version in (26, 30):
            return struct.unpack_from("<I", data, 0xD0)[0]
    except struct.error:
        pass
    return 0


def _parse_file_strings(data: bytes, version: int) -> list[str]:
    """
    Parse the referenced file strings section from a Prefetch file.

    The file strings section offset and length are stored at version-specific
    offsets in the Prefetch header.
    """
    try:
        if version == 17:
            strings_offset = struct.unpack_from("<I", data, 0x64)[0]
            strings_length = struct.unpack_from("<I", data, 0x68)[0]
        elif version == 23:
            strings_offset = struct.unpack_from("<I", data, 0x64)[0]
            strings_length = struct.unpack_from("<I", data, 0x68)[0]
        elif version in (26, 30):
            strings_offset = struct.unpack_from("<I", data, 0x64)[0]
            strings_length = struct.unpack_from("<I", data, 0x68)[0]
        else:
            return []

        section = data[strings_offset: strings_offset + strings_length]
        # File strings are null-terminated UTF-16LE entries
        raw_strings = section.decode("utf-16-le", errors="replace")
        return [s.upper() for s in raw_strings.split("\x00") if s.strip()]

    except (struct.error, UnicodeDecodeError):
        return []


# ---------------------------------------------------------------------------
# Core parser (pure Python fallback)
# ---------------------------------------------------------------------------

def _parse_prefetch_pure(data: bytes, pf_path: Path) -> Optional[list[PrefetchRecord]]:
    """
    Pure-Python Prefetch parser for v17, v23, v26, v30.

    Parameters
    ----------
    data : bytes
        Raw (decompressed if necessary) prefetch file content.
    pf_path : Path
        Path to the .pf file (used for filename extraction and logging).

    Returns
    -------
    list[PrefetchRecord] or None
        List of records (one per run time), or None if parsing failed.
    """
    if len(data) < 84:
        log.warning("Prefetch file too small to parse: %s (%d bytes)", pf_path.name, len(data))
        return None

    # Check SCCA signature at offset 4 (after 4-byte version field)
    if data[4:8] != _SCCA_SIGNATURE:
        log.warning("Invalid SCCA signature in %s", pf_path.name)
        return None

    version = struct.unpack_from("<I", data, 0)[0]
    if version not in (17, 23, 26, 30):
        log.warning("Unsupported Prefetch version %d in %s", version, pf_path.name)
        return None

    # Extract executable name from header (offset 16, 60 bytes, UTF-16LE null-padded)
    try:
        exe_raw = data[16:76]
        exe_name = exe_raw.decode("utf-16-le", errors="replace").split("\x00")[0].upper()
    except Exception:
        exe_name = ""

    pf_hash: str
    exe_from_filename: str
    exe_from_filename, pf_hash = _parse_pf_filename(pf_path.name)

    # Prefer header name, fall back to filename
    if not exe_name:
        exe_name = exe_from_filename

    run_count = _parse_run_count(data, version)

    if version in (17, 23):
        run_times = _parse_run_times_v17_v23(data, version)
    else:
        run_times = _parse_run_times_v26_v30(data)

    referenced_files = _parse_file_strings(data, version)

    if not run_times:
        log.debug("No run times found in %s — skipping", pf_path.name)
        return []

    records: list[PrefetchRecord] = []
    for ts in run_times:
        record = PrefetchRecord(
            timestamp=ts,
            source="prefetch",
            event_type=EventType.EXECUTION,
            path=normalise_path(exe_name),
            filename=exe_name,
            pid=None,
            details={
                "pf_version": version,
                "run_count": run_count,
            },
            executable=exe_name,
            run_count=run_count,
            run_times=run_times,
            referenced_files=referenced_files,
            pf_hash=pf_hash,
            pf_version=version,
            pf_filename=pf_path.name,
        )
        records.append(record)

    return records


# ---------------------------------------------------------------------------
# libscca-backed parser
# ---------------------------------------------------------------------------

def _parse_prefetch_libscca(pf_path: Path) -> Optional[list[PrefetchRecord]]:
    """
    Parse a Prefetch file using python-libscca.

    Returns None if libscca is not available (triggers fallback to pure parser).
    """
    try:
        import pyscca  # type: ignore
    except ImportError:
        return None

    try:
        pf = pyscca.open(str(pf_path))
    except Exception as exc:
        log.warning("libscca failed to open %s: %s", pf_path.name, exc)
        return None

    try:
        exe_name = (pf.executable_filename or "").upper()
        run_count = pf.prefetch_hash  # not run count — use run_count attribute
        try:
            run_count = pf.run_count
        except AttributeError:
            run_count = 0

        exe_from_filename, pf_hash = _parse_pf_filename(pf_path.name)
        if not exe_name:
            exe_name = exe_from_filename

        # Collect run times
        run_times: list[datetime] = []
        for i in range(8):
            try:
                ft_val = pf.get_last_run_time(i)
                if ft_val and ft_val.year > 1601:
                    dt = ft_val.replace(tzinfo=timezone.utc)
                    run_times.append(dt)
            except (AttributeError, IndexError, ValueError):
                break

        if not run_times:
            return []

        # Referenced files
        referenced: list[str] = []
        try:
            for i in range(pf.number_of_filenames):
                name = pf.get_filename(i)
                if name:
                    referenced.append(normalise_path(name))
        except Exception:
            pass

        records: list[PrefetchRecord] = []
        for ts in run_times:
            records.append(PrefetchRecord(
                timestamp=ts,
                source="prefetch",
                event_type=EventType.EXECUTION,
                path=normalise_path(exe_name),
                filename=exe_name,
                executable=exe_name,
                run_count=run_count,
                run_times=run_times,
                referenced_files=referenced,
                pf_hash=pf_hash,
                pf_version=0,
                pf_filename=pf_path.name,
            ))
        return records

    except Exception as exc:
        log.warning("libscca parse error for %s: %s", pf_path.name, exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_prefetch_file(
    path: Path,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[PrefetchRecord]:
    """
    Parse a single Windows Prefetch (.pf) file into PrefetchRecord objects.

    Tries python-libscca first, falls back to pure-Python parser.
    Handles MAM compression for Win10+ files.

    Parameters
    ----------
    path : Path
        Path to the .pf file.
    start : datetime, optional
        Discard records before this UTC-aware datetime.
    end : datetime, optional
        Discard records after this UTC-aware datetime.

    Returns
    -------
    list[PrefetchRecord]
        One record per execution timestamp. Empty list if parsing fails.

    Raises
    ------
    FileNotFoundError
        If the specified path does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"Prefetch file not found: {path}")

    # Try libscca first (handles compression natively on supported platforms)
    records = _parse_prefetch_libscca(path)

    if records is None:
        # libscca unavailable — use pure-Python parser
        try:
            data = path.read_bytes()
        except OSError as exc:
            log.error("Failed to read %s: %s", path, exc)
            return []

        if _is_mam_compressed(data):
            log.debug("MAM-compressed prefetch detected: %s", path.name)
            data = _decompress_mam(data)
            if data is None:
                log.warning(
                    "Cannot decompress MAM-compressed Prefetch file %s. "
                    "Install python-libscca for Win10+ support.",
                    path.name,
                )
                return []

        records = _parse_prefetch_pure(data, path)

    if records is None:
        return []

    # Apply time range filter
    filtered = []
    for r in records:
        if start and r.timestamp < start:
            continue
        if end and r.timestamp > end:
            continue
        filtered.append(r)

    return filtered


def parse_prefetch_directory(
    directory: Path,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[PrefetchRecord]:
    """
    Parse all .pf files in a directory and return combined PrefetchRecord list.

    Parameters
    ----------
    directory : Path
        Directory containing .pf files.
    start : datetime, optional
        Discard records before this UTC-aware datetime.
    end : datetime, optional
        Discard records after this UTC-aware datetime.

    Returns
    -------
    list[PrefetchRecord]
        All records from all .pf files, sorted by timestamp.

    Raises
    ------
    NotADirectoryError
        If the specified path is not a directory.
    """
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    pf_files = sorted(directory.glob("*.pf")) + sorted(directory.glob("*.PF"))
    pf_files = list(dict.fromkeys(pf_files))  # deduplicate

    if not pf_files:
        log.warning("No .pf files found in %s", directory)
        return []

    log.info("Found %d .pf file(s) in %s", len(pf_files), directory)

    all_records: list[PrefetchRecord] = []
    for pf_path in pf_files:
        try:
            file_records = parse_prefetch_file(pf_path, start, end)
            log.debug("  %s → %d record(s)", pf_path.name, len(file_records))
            all_records.extend(file_records)
        except FileNotFoundError:
            log.warning("Prefetch file disappeared: %s", pf_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("Unexpected error parsing %s: %s", pf_path.name, exc)

    all_records.sort(key=lambda r: r.timestamp)
    log.info("Prefetch parse complete: %d total records from %d files", len(all_records), len(pf_files))
    return all_records
