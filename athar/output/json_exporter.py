"""
athar.output.json_exporter
~~~~~~~~~~~~~~~~~~~~~~~~~~
Serialises analysis results to a structured JSON file.

Output schema
-------------
{
    "meta": {
        "tool": "Athar",
        "version": "0.1.0",
        "author": "Bernardo Sousa",
        "analysis_timestamp": "<ISO-8601>",
        "hostname": "<hostname>",
        "artefacts_processed": {
            "prefetch": 312,
            "usn": 48221,
            "evtx": 1204,
            "mft": 0
        },
        "time_range": {
            "start": "<ISO-8601 or null>",
            "end":   "<ISO-8601 or null>"
        }
    },
    "correlated_events": [ ... ],
    "raw_timeline": [ ... ]
}

Usage
-----
    from athar.output.json_exporter import export_json

    export_json(
        timeline=timeline,
        events=correlated_events,
        output_path=Path("athar_output/report.json"),
        hostname="WORKSTATION01",
        artefacts_processed={"prefetch": 312, "usn": 48221},
    )
"""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from athar import __version__
from athar.models.base import BaseRecord, CorrelatedEvent

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# JSON serialisation helpers
# ---------------------------------------------------------------------------

class _AtharEncoder(json.JSONEncoder):
    """
    Custom JSON encoder that handles types not supported by the stdlib encoder.

    - datetime → ISO-8601 string (always UTC-aware)
    - set → sorted list
    - Path → string
    """

    def default(self, obj: object) -> object:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return sorted(obj)
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def export_json(
    timeline: list[BaseRecord],
    events: list[CorrelatedEvent],
    output_path: Path,
    hostname: str = "",
    artefacts_processed: Optional[dict[str, int]] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    indent: int = 2,
) -> Path:
    """
    Serialise the full analysis to a structured JSON file.

    Parameters
    ----------
    timeline : list[BaseRecord]
        All artefact records in the merged timeline, sorted by timestamp.
    events : list[CorrelatedEvent]
        Correlated events produced by the rule engine.
    output_path : Path
        Destination file path. Parent directory must exist.
    hostname : str, optional
        System hostname to embed in the report metadata.
        Defaults to the local machine's hostname.
    artefacts_processed : dict[str, int], optional
        Record counts keyed by artefact source name.
        Computed from ``timeline`` if not provided.
    start : datetime, optional
        Analysis time range start (for metadata).
    end : datetime, optional
        Analysis time range end (for metadata).
    indent : int, optional
        JSON indentation level. Default: 2.

    Returns
    -------
    Path
        Absolute path to the written JSON file.
    """
    if not hostname:
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"

    if artefacts_processed is None:
        artefacts_processed = _count_by_source(timeline)

    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None

    if start:
        time_range_start = start.isoformat()
    elif timeline:
        time_range_start = timeline[0].timestamp.isoformat()

    if end:
        time_range_end = end.isoformat()
    elif timeline:
        time_range_end = timeline[-1].timestamp.isoformat()

    document = {
        "meta": {
            "tool": "Athar",
            "version": __version__,
            "author": "Bernardo Sousa",
            "analysis_timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "hostname": hostname,
            "artefacts_processed": artefacts_processed,
            "time_range": {
                "start": time_range_start,
                "end": time_range_end,
            },
            "summary": {
                "total_records": len(timeline),
                "total_correlated_events": len(events),
                "high_confidence": sum(1 for e in events if e.confidence == "high"),
                "medium_confidence": sum(1 for e in events if e.confidence == "medium"),
                "low_confidence": sum(1 for e in events if e.confidence == "low"),
                "lolbin_executions": sum(1 for e in events if "lolbin_execution" in e.tags),
            },
        },
        "correlated_events": [e.to_dict() for e in events],
        "raw_timeline": [r.to_dict() for r in timeline],
    }

    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(document, fh, cls=_AtharEncoder, indent=indent, ensure_ascii=False)
        log.info("JSON export written: %s (%d bytes)", output_path, output_path.stat().st_size)
    except OSError as exc:
        log.error("Failed to write JSON output to %s: %s", output_path, exc)
        raise

    return output_path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _count_by_source(timeline: list[BaseRecord]) -> dict[str, int]:
    """Count records per artefact source from the timeline."""
    counts: dict[str, int] = {"prefetch": 0, "mft": 0, "usn": 0, "evtx": 0}
    for record in timeline:
        counts[record.source] = counts.get(record.source, 0) + 1
    return counts
