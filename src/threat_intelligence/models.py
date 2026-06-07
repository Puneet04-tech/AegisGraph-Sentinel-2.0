"""Data models for Threat Intelligence & Fraud Command Center.

All models are database-agnostic dataclasses.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Set


def _utcnow() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12].upper()}"


@dataclass
class ThreatIndicator:
    """A single indicator of compromise (IOC) e.g. malicious IP or Device ID."""
    indicator_type: str                  # IP | DEVICE | ACCOUNT
    value: str                           # e.g. "192.168.1.1" or "DEV123"
    source_feed: str                     # e.g. "INTERNAL_ALERTS" or "TOR_EXIT_NODE_FEED"
    threat_score: float                  # 0.0 to 1.0
    confidence: float                    # 0.0 to 1.0
    
    indicator_id: str = field(default_factory=lambda: _new_id("IND"))
    last_seen: str = field(default_factory=_utcnow)


@dataclass
class ThreatActor:
    """Profile of a repeat offender or known threat actor group."""
    name: str
    risk_score: float                    # Aggregated threat risk score (0.0 to 1.0)
    
    actor_id: str = field(default_factory=lambda: _new_id("ACT"))
    associated_accounts: Set[str] = field(default_factory=set)
    associated_devices: Set[str] = field(default_factory=set)
    associated_ips: Set[str] = field(default_factory=set)
    campaign_ids: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_utcnow)
    updated_at: str = field(default_factory=_utcnow)


@dataclass
class FraudCampaign:
    """Coordinated fraud campaign targeting multiple accounts or transactions."""
    name: str
    description: str
    attack_pattern: str                  # e.g. "Credential Stuffing" or "Mule Laundering Ring"
    severity: str                        # LOW | MEDIUM | HIGH | CRITICAL
    status: str                          # ACTIVE | CONTAINED | RESOLVED
    
    campaign_id: str = field(default_factory=lambda: _new_id("CMP"))
    threat_actor_id: Optional[str] = None
    case_ids: List[str] = field(default_factory=list)
    start_time: str = field(default_factory=_utcnow)
    end_time: Optional[str] = None


@dataclass
class AttackPattern:
    """Standard threat vectors or patterns matched during correlation."""
    name: str
    description: str
    tactics: List[str]                   # e.g. ["TA0008", "Credential Access"]
    
    pattern_id: str = field(default_factory=lambda: _new_id("PAT"))


@dataclass
class ThreatCorrelation:
    """Correlation group containing related fraud cases."""
    case_ids: List[str]
    similarity_score: float              # 0.0 to 1.0 indicating degree of correlation
    common_features: List[str]           # e.g. ["ip=103.5.5.5", "device=DEV987"]
    description: str
    
    correlation_id: str = field(default_factory=lambda: _new_id("COR"))
    created_at: str = field(default_factory=_utcnow)
