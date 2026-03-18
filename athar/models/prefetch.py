"""
athar.models.prefetch
~~~~~~~~~~~~~~~~~~~~~
Data model for Windows Prefetch artefact records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from athar.models.base import BaseRecord


@dataclass
class PrefetchRecord(BaseRecord):
    """
    Record produced by parsing a Windows Prefetch (.pf) file.

    One PrefetchRecord is emitted per execution timestamp found in the file.
    A single .pf file may yield up to 8 records (Win10+ stores up to 8 run times).

    Attributes
    ----------
    executable : str
        Executable name extracted from the prefetch filename, without the hash
        suffix (e.g. "CMD.EXE" from "CMD.EXE-AB1234CD.pf").
    run_count : int
        Total number of times the executable has been run, as recorded by the OS.
    run_times : list[datetime]
        All UTC-aware run timestamps found in the file. The record's ``timestamp``
        field is set to the specific run time this record represents.
    referenced_files : list[str]
        Normalised paths of files referenced during execution (up to 1024).
    referenced_volumes : list[str]
        Volume device paths referenced by the executable.
    pf_version : int
        Prefetch format version: 17 (XP), 23 (Vista/7), 26 (Win8), 30 (Win10+).
    """

    executable: str = ""
    run_count: int = 0
    run_times: list[datetime] = field(default_factory=list)
    referenced_files: list[str] = field(default_factory=list)
    referenced_volumes: list[str] = field(default_factory=list)
    pf_version: int = 0
    pf_hash: str = ""
    pf_filename: str = ""

    def to_dict(self) -> dict:
        """Serialise to plain dictionary, extending BaseRecord.to_dict()."""
        base = super().to_dict()
        base.update({
            "executable": self.executable,
            "run_count": self.run_count,
            "run_times": [t.isoformat() for t in self.run_times],
            "pf_version": self.pf_version,
            "referenced_files_count": len(self.referenced_files),
        })
        return base
