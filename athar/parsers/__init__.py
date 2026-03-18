"""
athar.parsers
~~~~~~~~~~~~~
Artefact parsers for Windows forensic sources:
- Prefetch (.pf files)
- Master File Table ($MFT)
- USN Journal ($UsnJrnl:$J)
- Event Logs (.evtx files)
"""

from athar.parsers.usn_parser import parse_usn_journal
from athar.parsers.evtx_parser import parse_evtx_file, parse_evtx_directory
from athar.parsers.prefetch_parser import parse_prefetch_file, parse_prefetch_directory

__all__ = [
    "parse_usn_journal",
    "parse_evtx_file",
    "parse_evtx_directory",
    "parse_prefetch_file",
    "parse_prefetch_directory",
]
