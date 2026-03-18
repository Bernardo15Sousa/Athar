"""
athar.correlation
~~~~~~~~~~~~~~~~~
Timeline merge, enrichment, and correlation rule engine.
"""

from athar.correlation.engine import build_timeline, correlate, get_stats
from athar.correlation.rules import ALL_RULES
from athar.correlation.enrichment import is_lolbin, get_lolbin_mitre, enrich_record

__all__ = [
    "build_timeline",
    "correlate",
    "get_stats",
    "ALL_RULES",
    "is_lolbin",
    "get_lolbin_mitre",
    "enrich_record",
]
