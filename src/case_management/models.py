"""Data models for Fraud Case Management.

All models are pure Python dataclasses to avoid DB dependencies.
The in-memory CaseStore (store.py) manages their lifecycle.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


def _utcnow() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(prefix: str = "CASE") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12].upper()}"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class CaseStatus(str, Enum):
    """Lifecycle states for a FraudCase."""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CasePriority(str, Enum):
    """Priority tiers for a FraudCase."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceType(str, Enum):
    """Types of evidence that can be attached to a case."""
    TRANSACTION_LINK = "TRANSACTION_LINK"
    GRAPH_SNAPSHOT = "GRAPH_SNAPSHOT"
    NOTE = "NOTE"
    DOCUMENT = "DOCUMENT"


# ---------------------------------------------------------------------------
# Valid status transitions (state machine)
# ---------------------------------------------------------------------------

VALID_TRANSITIONS: dict[CaseStatus, set[CaseStatus]] = {
    CaseStatus.OPEN:        {CaseStatus.IN_PROGRESS, CaseStatus.ESCALATED, CaseStatus.CLOSED},
    CaseStatus.IN_PROGRESS: {CaseStatus.ESCALATED, CaseStatus.RESOLVED, CaseStatus.CLOSED},
    CaseStatus.ESCALATED:   {CaseStatus.IN_PROGRESS, CaseStatus.RESOLVED, CaseStatus.CLOSED},
    CaseStatus.RESOLVED:    {CaseStatus.CLOSED},
    CaseStatus.CLOSED:      set(),  # terminal state
}


def validate_status_transition(current: CaseStatus, new: CaseStatus) -> None:
    """Raise ValueError if the transition is not permitted."""
    if new == current:
        return
    allowed = VALID_TRANSITIONS.get(current, set())
    if new not in allowed:
        raise ValueError(
            f"Invalid status transition: {current.value} → {new.value}. "
            f"Allowed: {[s.value for s in allowed] or 'none (terminal state)'}."
        )


# ---------------------------------------------------------------------------
# Core dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FraudCase:
    """Represents a fraud investigation case."""
    transaction_id: str
    risk_score: float
    decision: str                         # ALLOW | REVIEW | BLOCK

    # Auto-populated fields
    case_id: str = field(default_factory=lambda: _new_id("CASE"))
    status: CaseStatus = CaseStatus.OPEN
    priority: CasePriority = CasePriority.MEDIUM
    assigned_analyst: Optional[str] = None
    created_at: str = field(default_factory=_utcnow)
    updated_at: str = field(default_factory=_utcnow)
    tags: List[str] = field(default_factory=list)

    # Child records (stored separately in the store, referenced here for
    # fast serialisation)
    comment_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)

    def touch(self) -> None:
        """Update the updated_at timestamp."""
        self.updated_at = _utcnow()


@dataclass
class CaseComment:
    """An analyst's investigation note attached to a case."""
    case_id: str
    analyst_id: str
    text: str

    comment_id: str = field(default_factory=lambda: _new_id("CMT"))
    created_at: str = field(default_factory=_utcnow)


@dataclass
class CaseEvidence:
    """A piece of evidence attached to a fraud case."""
    case_id: str
    analyst_id: str
    evidence_type: EvidenceType
    description: str
    reference_id: Optional[str] = None   # e.g. transaction_id or graph node id

    evidence_id: str = field(default_factory=lambda: _new_id("EVD"))
    created_at: str = field(default_factory=_utcnow)


@dataclass
class CaseAuditEvent:
    """An immutable audit record of a state-changing action on a case."""
    case_id: str
    analyst_id: str
    action: str                          # e.g. "STATUS_CHANGED", "ANALYST_ASSIGNED"
    old_value: Optional[str] = None
    new_value: Optional[str] = None

    event_id: str = field(default_factory=lambda: _new_id("AUD"))
    timestamp: str = field(default_factory=_utcnow)
