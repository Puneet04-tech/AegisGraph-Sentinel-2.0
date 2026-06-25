"""
Data models for the Sentinel log archival system.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ArchivalStatus(str, Enum):
    """Lifecycle state of a single archival run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"  # some batches failed but others succeeded


@dataclass
class SentinelLog:
    """
    Represents a single Sentinel event or threat log entry.

    This is the primary document stored in the hot collection.  Any field
    added here should be mirrored in the archive counterpart so that
    historical queries return the same shape as live queries.
    """

    log_id: str
    event_type: str                         # e.g. "fraud_check", "threat_detected"
    source_account: Optional[str]
    target_account: Optional[str]
    risk_score: float
    decision: str                           # ALLOW | REVIEW | BLOCK
    metadata: Dict[str, Any]
    created_at: datetime
    archived: bool = False
    archived_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id": self.log_id,
            "event_type": self.event_type,
            "source_account": self.source_account,
            "target_account": self.target_account,
            "risk_score": self.risk_score,
            "decision": self.decision,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "archived": self.archived,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SentinelLog":
        return cls(
            log_id=data["log_id"],
            event_type=data["event_type"],
            source_account=data.get("source_account"),
            target_account=data.get("target_account"),
            risk_score=float(data.get("risk_score", 0.0)),
            decision=data.get("decision", "ALLOW"),
            metadata=data.get("metadata", {}),
            created_at=_parse_dt(data["created_at"]),
            archived=data.get("archived", False),
            archived_at=_parse_dt(data["archived_at"]) if data.get("archived_at") else None,
        )


@dataclass
class ArchiveRecord:
    """
    A log entry that has been migrated to cold storage.

    Identical to SentinelLog but always has `archived=True` and a populated
    `archived_at` timestamp.  The `archive_run_id` links the record back to
    the specific archival run that moved it.
    """

    log_id: str
    event_type: str
    source_account: Optional[str]
    target_account: Optional[str]
    risk_score: float
    decision: str
    metadata: Dict[str, Any]
    created_at: datetime
    archived_at: datetime
    archive_run_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id": self.log_id,
            "event_type": self.event_type,
            "source_account": self.source_account,
            "target_account": self.target_account,
            "risk_score": self.risk_score,
            "decision": self.decision,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "archived_at": self.archived_at.isoformat(),
            "archive_run_id": self.archive_run_id,
        }

    @classmethod
    def from_sentinel_log(
        cls,
        log: SentinelLog,
        archive_run_id: str,
        archived_at: Optional[datetime] = None,
    ) -> "ArchiveRecord":
        """Promote a SentinelLog into an ArchiveRecord."""
        return cls(
            log_id=log.log_id,
            event_type=log.event_type,
            source_account=log.source_account,
            target_account=log.target_account,
            risk_score=log.risk_score,
            decision=log.decision,
            metadata=log.metadata,
            created_at=log.created_at,
            archived_at=archived_at or datetime.now(timezone.utc),
            archive_run_id=archive_run_id,
        )


@dataclass
class ArchivalRunSummary:
    """
    Audit record for a single archival cycle.

    Written to the store after every scheduled run so operators can inspect
    history, detect gaps, and diagnose failures.
    """

    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    status: ArchivalStatus = ArchivalStatus.PENDING
    threshold_days: int = 30
    documents_scanned: int = 0
    documents_archived: int = 0
    documents_failed: int = 0
    error_message: Optional[str] = None

    def finish(
        self,
        *,
        archived: int,
        failed: int,
        scanned: int,
        error: Optional[str] = None,
    ) -> None:
        self.completed_at = datetime.now(timezone.utc)
        self.documents_scanned = scanned
        self.documents_archived = archived
        self.documents_failed = failed
        self.error_message = error

        if error and archived == 0:
            self.status = ArchivalStatus.FAILED
        elif failed > 0:
            self.status = ArchivalStatus.PARTIAL
        else:
            self.status = ArchivalStatus.COMPLETED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status.value,
            "threshold_days": self.threshold_days,
            "documents_scanned": self.documents_scanned,
            "documents_archived": self.documents_archived,
            "documents_failed": self.documents_failed,
            "error_message": self.error_message,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_dt(value: Any) -> datetime:
    """Parse an ISO 8601 string or passthrough an existing datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    raise ValueError(f"Cannot parse datetime from {value!r}")
