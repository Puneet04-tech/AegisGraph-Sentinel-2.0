"""Data models for Digital Forensics & Investigation Timeline Engine.

All models are database-agnostic dataclasses.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utcnow() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12].upper()}"


@dataclass
class Evidence:
    """Forensic evidence entry containing verified hashes for tamper detection."""
    case_id: str
    type: str                  # e.g., "IP", "DEVICE", "ACCOUNT", "TRANSACTION", "METADATA"
    source: str                # e.g., "IP_API", "DEVICE_FINGERPRINT", "USER_DATABASE"
    value: str                 # The evidence content
    hash: str                  # SHA256 of value
    
    id: str = field(default_factory=lambda: _new_id("EVI"))
    created_at: str = field(default_factory=_utcnow)


@dataclass
class Investigation:
    """Investigation case tracking workflow and lifecycle."""
    title: str
    analyst_id: str
    status: str = "OPEN"       # OPEN | ASSIGNED | UNDER_REVIEW | CLOSED
    
    id: str = field(default_factory=lambda: _new_id("INV"))
    case_ids: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_utcnow)
    updated_at: str = field(default_factory=_utcnow)


@dataclass
class TimelineEvent:
    """An event tracked in the investigation timeline."""
    investigation_id: str
    event_type: str            # e.g., "CASE_LINKED", "EVIDENCE_ADDED", "STATUS_CHANGE", "ANALYST_NOTE", "TRANSACTION"
    entity_id: str             # ID of related entity (case, transaction, indicator, etc.)
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    id: str = field(default_factory=lambda: _new_id("EVT"))
    timestamp: str = field(default_factory=_utcnow)


@dataclass
class AttackChain:
    """Reconstructed path of coordinated attacks attributing cases to campaigns/actors."""
    campaign_id: str
    steps: List[Dict[str, Any]]  # List of ordered trace hops
    confidence_score: float      # 0.0 to 1.0
    
    id: str = field(default_factory=lambda: _new_id("CHN"))
    created_at: str = field(default_factory=_utcnow)

