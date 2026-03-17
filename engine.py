"""
athar.correlation.engine
~~~~~~~~~~~~~~~~~~~~~~~~
Timeline merge and correlation rule orchestration.

The engine:
1. Accepts parsed artefact records from all sources
2. Merges them into a unified, sorted timeline
3. Runs all correlation rules against the full record set
4. Returns a list of CorrelatedEvent objects sorted by window_start

Usage
-----
    from athar.correlation.engine import correlate

    events = correlate(
        prefetch=prefetch_records,
        mft=mft_records,
        usn=usn_records,
        evtx=evtx_records,
    )
    for event in events:
        print(event.confidence, event.tags, event.notes)
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from athar.models.base import BaseRecord, CorrelatedEvent
from athar.models.prefetch import PrefetchRecord
from athar.models.mft import MFTRecord
from athar.models.usn import USNRecord
from athar.models.evtx import EventLogRecord
from athar.correlation.rules import ALL_RULES

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Timeline merge
# ---------------------------------------------------------------------------

def build_timeline(
    prefetch: list[PrefetchRecord] | None = None,
    mft: list[MFTRecord] | None = None,
    usn: list[USNRecord] | None = None,
    evtx: list[EventLogRecord] | None = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[BaseRecord]:
    """
    Merge artefact records from all sources into a single sorted timeline.

    Parameters
    ----------
    prefetch : list[PrefetchRecord], optional
    mft : list[MFTRecord], optional
    usn : list[USNRecord], optional
    evtx : list[EventLogRecord], optional
    start : datetime, optional
        Discard records before this UTC-aware datetime.
    end : datetime, optional
        Discard records after this UTC-aware datetime.

    Returns
    -------
    list[BaseRecord]
        All records merged and sorted ascending by timestamp.
    """
    all_records: list[BaseRecord] = []

    for source_name, source_records in [
        ("prefetch", prefetch or []),
        ("mft", mft or []),
        ("usn", usn or []),
        ("evtx", evtx or []),
    ]:
        count_before = len(source_records)
        filtered = source_records

        if start:
            filtered = [r for r in filtered if r.timestamp >= start]
        if end:
            filtered = [r for r in filtered if r.timestamp <= end]

        log.debug(
            "Timeline merge: %s → %d records (%d filtered out)",
            source_name, len(filtered), count_before - len(filtered)
        )
        all_records.extend(filtered)

    all_records.sort(key=lambda r: r.timestamp)
    log.info("Timeline built: %d total records across all sources", len(all_records))
    return all_records


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def correlate(
    prefetch: list[PrefetchRecord] | None = None,
    mft: list[MFTRecord] | None = None,
    usn: list[USNRecord] | None = None,
    evtx: list[EventLogRecord] | None = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    rules: list | None = None,
) -> tuple[list[BaseRecord], list[CorrelatedEvent]]:
    """
    Run all correlation rules against the merged artefact timeline.

    Parameters
    ----------
    prefetch, mft, usn, evtx : lists of artefact records, optional
    start : datetime, optional
        Timeline filter start.
    end : datetime, optional
        Timeline filter end.
    rules : list of rule functions, optional
        Override the default rule set. Defaults to ALL_RULES.

    Returns
    -------
    tuple[list[BaseRecord], list[CorrelatedEvent]]
        (timeline, correlated_events) where:
        - timeline is all records sorted by timestamp
        - correlated_events is all rule findings sorted by window_start
    """
    if rules is None:
        rules = ALL_RULES

    timeline = build_timeline(prefetch, mft, usn, evtx, start, end)

    if not timeline:
        log.warning("Timeline is empty — no records to correlate")
        return [], []

    log.info("Running %d correlation rules against %d records", len(rules), len(timeline))

    all_events: list[CorrelatedEvent] = []
    for rule_fn in rules:
        try:
            findings = rule_fn(timeline)
            if findings:
                log.info("  %s → %d finding(s)", rule_fn.__name__, len(findings))
            all_events.extend(findings)
        except Exception as exc:  # noqa: BLE001
            log.error("Rule %s raised an exception: %s", rule_fn.__name__, exc, exc_info=True)

    all_events.sort(key=lambda e: e.window_start)

    high = sum(1 for e in all_events if e.confidence == "high")
    medium = sum(1 for e in all_events if e.confidence == "medium")
    low = sum(1 for e in all_events if e.confidence == "low")

    log.info(
        "Correlation complete: %d total findings (high=%d, medium=%d, low=%d)",
        len(all_events), high, medium, low
    )

    return timeline, all_events


def get_stats(
    timeline: list[BaseRecord],
    events: list[CorrelatedEvent],
) -> dict:
    """
    Compute summary statistics for reporting.

    Parameters
    ----------
    timeline : list[BaseRecord]
    events : list[CorrelatedEvent]

    Returns
    -------
    dict
        Keys: total_records, records_by_source, total_events, events_by_confidence,
              time_range_start, time_range_end, lolbin_count, unique_binaries
    """
    from athar.correlation.enrichment import is_lolbin

    records_by_source: dict[str, int] = {}
    for r in timeline:
        records_by_source[r.source] = records_by_source.get(r.source, 0) + 1

    events_by_confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for e in events:
        events_by_confidence[e.confidence] = events_by_confidence.get(e.confidence, 0) + 1

    lolbin_events = [e for e in events if "lolbin_execution" in e.tags]
    unique_lolbins = {e.primary_filename for e in lolbin_events}

    time_start = timeline[0].timestamp.isoformat() if timeline else None
    time_end = timeline[-1].timestamp.isoformat() if timeline else None

    return {
        "total_records": len(timeline),
        "records_by_source": records_by_source,
        "total_events": len(events),
        "events_by_confidence": events_by_confidence,
        "time_range_start": time_start,
        "time_range_end": time_end,
        "lolbin_count": len(lolbin_events),
        "unique_lolbins": sorted(unique_lolbins),
    }
