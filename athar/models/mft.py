"""
athar.models.mft
~~~~~~~~~~~~~~~~
Data model for Windows Master File Table ($MFT) artefact records.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from athar.models.base import BaseRecord


@dataclass
class MFTRecord(BaseRecord):
    """
    Record produced by parsing an entry from the NTFS Master File Table ($MFT).

    Each MFT entry contains two sets of MACB timestamps:
    - $STANDARD_INFORMATION (SI): easily modified by tools, often timestomped.
    - $FILE_NAME (FN): harder to alter without low-level access.

    A divergence > 2 seconds between SI and FN created timestamps is flagged
    as a potential timestomping indicator (``timestomp_suspect = True``).

    Attributes
    ----------
    entry_number : int
        MFT entry number (low 48 bits of the file reference number).
    sequence_number : int
        MFT sequence number (high 16 bits of the file reference number).
        Incremented each time the entry is reused after deletion.
    parent_entry : int
        MFT entry number of the parent directory.
    si_created : datetime, optional
        $STANDARD_INFORMATION created timestamp (UTC-aware).
    si_modified : datetime, optional
        $STANDARD_INFORMATION last-modified timestamp (UTC-aware).
    si_mft_modified : datetime, optional
        $STANDARD_INFORMATION MFT-entry-modified timestamp (UTC-aware).
    si_accessed : datetime, optional
        $STANDARD_INFORMATION last-accessed timestamp (UTC-aware).
    fn_created : datetime, optional
        $FILE_NAME created timestamp (UTC-aware).
    fn_modified : datetime, optional
        $FILE_NAME last-modified timestamp (UTC-aware).
    fn_mft_modified : datetime, optional
        $FILE_NAME MFT-entry-modified timestamp (UTC-aware).
    fn_accessed : datetime, optional
        $FILE_NAME last-accessed timestamp (UTC-aware).
    file_size : int
        Logical file size in bytes (from non-resident $DATA attribute).
    is_directory : bool
        True if the MFT entry represents a directory.
    is_deleted : bool
        True if the MFT entry's allocation flag is unset (file was deleted).
    timestomp_suspect : bool
        True if SI created and FN created differ by more than 2 seconds.
    """

    entry_number: int = 0
    sequence_number: int = 0
    parent_entry: int = 0
    si_created: Optional[datetime] = None
    si_modified: Optional[datetime] = None
    si_mft_modified: Optional[datetime] = None
    si_accessed: Optional[datetime] = None
    fn_created: Optional[datetime] = None
    fn_modified: Optional[datetime] = None
    fn_mft_modified: Optional[datetime] = None
    fn_accessed: Optional[datetime] = None
    file_size: int = 0
    is_directory: bool = False
    is_deleted: bool = False
    timestomp_suspect: bool = False

    def to_dict(self) -> dict:
        """Serialise to plain dictionary, extending BaseRecord.to_dict()."""
        base = super().to_dict()
        base.update({
            "entry_number": self.entry_number,
            "sequence_number": self.sequence_number,
            "parent_entry": self.parent_entry,
            "si_created": self.si_created.isoformat() if self.si_created else None,
            "si_modified": self.si_modified.isoformat() if self.si_modified else None,
            "si_mft_modified": self.si_mft_modified.isoformat() if self.si_mft_modified else None,
            "si_accessed": self.si_accessed.isoformat() if self.si_accessed else None,
            "fn_created": self.fn_created.isoformat() if self.fn_created else None,
            "fn_modified": self.fn_modified.isoformat() if self.fn_modified else None,
            "fn_mft_modified": self.fn_mft_modified.isoformat() if self.fn_mft_modified else None,
            "fn_accessed": self.fn_accessed.isoformat() if self.fn_accessed else None,
            "file_size": self.file_size,
            "is_directory": self.is_directory,
            "is_deleted": self.is_deleted,
            "timestomp_suspect": self.timestomp_suspect,
        })
        return base
