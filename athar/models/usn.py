"""
athar.models.usn
~~~~~~~~~~~~~~~~
Data model for Windows USN Journal ($UsnJrnl:$J) artefact records.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from athar.models.base import BaseRecord


@dataclass
class USNRecord(BaseRecord):
    """
    Record produced by parsing a USN_RECORD_V2 entry from the USN Journal.

    The USN Journal records all file system change operations on an NTFS volume.
    Each record captures a single change event for a specific file, identified by
    its MFT file reference number.

    Attributes
    ----------
    usn : int
        Update Sequence Number — monotonically increasing journal offset.
        Can be used to reconstruct the chronological order of changes at
        sub-second resolution when timestamps collide.
    file_reference : int
        Full 64-bit MFT file reference number (sequence << 48 | entry_number).
        Low 48 bits = MFT entry number; high 16 bits = sequence number.
    parent_reference : int
        Full 64-bit MFT file reference number of the parent directory.
    reason_flags : list[str]
        Human-readable reason flag names decoded from the Reason bitmask
        (e.g. ["FILE_CREATE", "CLOSE"]).
    reason_raw : int
        Raw Reason DWORD bitmask as recorded in the journal entry.
    """

    usn: int = 0
    file_reference: int = 0
    parent_reference: int = 0
    reason_flags: list[str] = field(default_factory=list)
    reason_raw: int = 0
    file_attributes: int = 0
    source_info: int = 0

    @property
    def mft_entry(self) -> int:
        """MFT entry number — low 48 bits of the file reference number."""
        return self.file_reference & 0x0000FFFFFFFFFFFF

    @property
    def mft_sequence(self) -> int:
        """MFT sequence number — high 16 bits of the file reference number."""
        return (self.file_reference >> 48) & 0xFFFF

    def to_dict(self) -> dict:
        """Serialise to plain dictionary, extending BaseRecord.to_dict()."""
        base = super().to_dict()
        base.update({
            "usn": self.usn,
            "file_reference": self.file_reference,
            "mft_entry": self.mft_entry,
            "mft_sequence": self.mft_sequence,
            "parent_reference": self.parent_reference,
            "reason_flags": self.reason_flags,
            "reason_raw": hex(self.reason_raw),
            "file_attributes": hex(self.file_attributes),
        })
        return base
