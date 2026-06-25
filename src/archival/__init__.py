"""
Sentinel Log Archival Package

Provides automated data lifecycle management for Sentinel event and threat logs.
Aging documents are migrated from the primary (hot) store into a cold-storage
archive collection, keeping real-time graph queries fast while preserving full
historical data for on-demand queries.
"""

from .models import ArchiveRecord, ArchivalRunSummary, ArchivalStatus
from .store import SentinelLogStore
from .archival_service import ArchivalService
from .scheduler import ArchivalScheduler

__all__ = [
    "ArchiveRecord",
    "ArchivalRunSummary",
    "ArchivalStatus",
    "SentinelLogStore",
    "ArchivalService",
    "ArchivalScheduler",
]
