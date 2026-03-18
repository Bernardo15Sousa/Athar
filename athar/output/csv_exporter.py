"""
athar.output.csv_exporter
~~~~~~~~~~~~~~~~~~~~~~~~~
Exports the analysis timeline and correlated events to CSV files.

Two files are produced:

1. ``<stem>_timeline.csv`` — Flat chronological list of every artefact record,
   annotated with correlation data (tags, confidence, MITRE, notes) for records
   that appear in a CorrelatedEvent. Suitable for loading in Timeline Explorer
   (EZ Tools) and similar tools.

2. ``<stem>_findings.csv`` — One row per CorrelatedEvent, sorted by window_start.
   Suitable for a quick analyst review without the volume of the full timeline.

Column order for the timeline CSV is kept close to the Timeline Explorer format
used by Eric Zimmerman's tools — timestamp first, then source, type, and path.

Usage
-----
    from athar.output.csv_exporter import export_csv

    timeline_path, findings_path = export_csv(
        timeline=timeline,
        events=correlated_events,
        output_path=Path("athar_output/report.csv"),
    )
"""

from __future__ import annotations

import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from athar.models.base import BaseRecord, CorrelatedEvent

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

# Timeline CSV — one row per BaseRecord, enriched with correlation metadata
_TIMELINE_COLUMNS = [
    "timestamp",
    "source",
    "event_type",
    "path",
    "filename",
    "pid",
    "tags",
    "confidence",
    "mitre_tags",
    "notes",
    "rule_ids",
]

# Findings CSV — one row per CorrelatedEvent
_FINDINGS_COLUMNS = [
    "window_start",
    "window_end",
    "rule_id",
    "confidence",
    "primary_filename",
    "primary_path",
    "tags",
    "mitre_tags",
    "notes",
    "source_set",
    "record_count",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def export_csv(
    timeline: list[BaseRecord],
    events: list[CorrelatedEvent],
    output_path: Path,
) -> tuple[Path, Path]:
    """
    Export the timeline and correlated findings to two CSV files.

    Parameters
    ----------
    timeline : list[BaseRecord]
        All artefact records sorted by timestamp.
    events : list[CorrelatedEvent]
        Correlated events from the rule engine, sorted by window_start.
    output_path : Path
        Base output path. The stem is reused to produce two files:
        ``<stem>_timeline.csv`` and ``<stem>_findings.csv``.

    Returns
    -------
    tuple[Path, Path]
        (timeline_csv_path, findings_csv_path)
    """
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    stem = output_path.stem
    parent = output_path.parent

    timeline_path = parent / f"{stem}_timeline.csv"
    findings_path = parent / f"{stem}_findings.csv"

    # Build a lookup: record id → list of CorrelatedEvents it contributes to
    record_event_map = _build_record_event_map(timeline, events)

    _write_timeline_csv(timeline, record_event_map, timeline_path)
    _write_findings_csv(events, findings_path)

    return timeline_path, findings_path


# ---------------------------------------------------------------------------
# Internal — timeline CSV
# ---------------------------------------------------------------------------

def _build_record_event_map(
    timeline: list[BaseRecord],
    events: list[CorrelatedEvent],
) -> dict[int, list[CorrelatedEvent]]:
    """
    Map each record's object id to the CorrelatedEvents it contributes to.

    Uses Python's ``id()`` to match record instances, which is safe here
    because the same record objects flow from parsers → engine → rules.
    """
    mapping: dict[int, list[CorrelatedEvent]] = {}
    for event in events:
        for record in event.records:
            rid = id(record)
            if rid not in mapping:
                mapping[rid] = []
            mapping[rid].append(event)
    return mapping


def _write_timeline_csv(
    timeline: list[BaseRecord],
    record_event_map: dict[int, list[CorrelatedEvent]],
    path: Path,
) -> None:
    """Write the flat timeline CSV, one row per record."""
    try:
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_TIMELINE_COLUMNS)
            writer.writeheader()

            for record in timeline:
                correlated = record_event_map.get(id(record), [])

                # Aggregate correlation metadata from all matching events
                all_tags: list[str] = []
                all_mitre: list[str] = []
                all_notes: list[str] = []
                all_rule_ids: list[str] = []
                confidences: list[str] = []

                for event in correlated:
                    all_tags.extend(event.tags)
                    all_mitre.extend(event.mitre_tags)
                    all_notes.extend(event.notes)
                    if event.rule_id:
                        all_rule_ids.append(event.rule_id)
                    confidences.append(event.confidence)

                # Deduplicate while preserving order
                unique_tags = _dedup(all_tags)
                unique_mitre = _dedup(all_mitre)
                unique_rule_ids = _dedup(all_rule_ids)

                # Pick highest confidence level if record appears in multiple events
                confidence = _highest_confidence(confidences)

                writer.writerow({
                    "timestamp": record.timestamp.isoformat(),
                    "source": record.source,
                    "event_type": record.event_type,
                    "path": record.path,
                    "filename": record.filename,
                    "pid": record.pid if record.pid is not None else "",
                    "tags": "|".join(unique_tags),
                    "confidence": confidence,
                    "mitre_tags": "|".join(unique_mitre),
                    "notes": " // ".join(all_notes),
                    "rule_ids": "|".join(unique_rule_ids),
                })

        log.info(
            "Timeline CSV written: %s (%d records, %d bytes)",
            path, len(timeline), path.stat().st_size,
        )

    except OSError as exc:
        log.error("Failed to write timeline CSV to %s: %s", path, exc)
        raise


# ---------------------------------------------------------------------------
# Internal — findings CSV
# ---------------------------------------------------------------------------

def _write_findings_csv(events: list[CorrelatedEvent], path: Path) -> None:
    """Write the findings summary CSV, one row per CorrelatedEvent."""
    try:
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_FINDINGS_COLUMNS)
            writer.writeheader()

            for event in sorted(events, key=lambda e: e.window_start):
                writer.writerow({
                    "window_start": event.window_start.isoformat(),
                    "window_end": event.window_end.isoformat(),
                    "rule_id": event.rule_id,
                    "confidence": event.confidence,
                    "primary_filename": event.primary_filename,
                    "primary_path": event.primary_path,
                    "tags": "|".join(event.tags),
                    "mitre_tags": "|".join(event.mitre_tags),
                    "notes": " // ".join(event.notes),
                    "source_set": "|".join(sorted(event.source_set)),
                    "record_count": event.record_count if hasattr(event, "record_count") else len(event.records),
                })

        log.info(
            "Findings CSV written: %s (%d events, %d bytes)",
            path, len(events), path.stat().st_size,
        )

    except OSError as exc:
        log.error("Failed to write findings CSV to %s: %s", path, exc)
        raise


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _dedup(items: list[str]) -> list[str]:
    """Remove duplicates from a list while preserving insertion order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


_CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}


def _highest_confidence(confidences: list[str]) -> str:
    """Return the highest confidence level from a list, or empty string."""
    if not confidences:
        return ""
    return max(confidences, key=lambda c: _CONFIDENCE_RANK.get(c, -1))
