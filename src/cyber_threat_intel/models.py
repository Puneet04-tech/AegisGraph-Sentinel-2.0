"""
Cyber Threat Intelligence Models.

Models for enterprise CTI platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class IOCType(str, Enum):
    """Indicator of Compromise types."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    MALWARE = "malware"
    VULNERABILITY = "vulnerability"


class ThreatLevel(str, Enum):
    """Threat levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ThreatCategory(str, Enum):
    """Threat categories."""
    APT = "apt"
    CRIMEWARE = "crimeware"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    SPYWARE = "spyware"


class FeedSource(str, Enum):
    """Threat feed sources."""
    OSINT = "osint"
    COMMERCIAL = "commercial"
    GOVERNMENT = "government"
    ISAC = "isac"
    SHARING_GROUP = "sharing_group"


@dataclass
class IOC:
    """Indicator of Compromise."""
    ioc_id: str
    indicator_type: IOCType
    value: str
    threat_level: ThreatLevel
    confidence: float = 0.5
    tags: List[str] = field(default_factory=list)
    source: Optional[str] = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatActor:
    """Threat actor profile."""
    actor_id: str
    name: str
    category: ThreatCategory
    aliases: List[str] = field(default_factory=list)
    motivation: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    target_sectors: List[str] = field(default_factory=list)
    geolocation: List[str] = field(default_factory=list)
    associated_actors: List[str] = field(default_factory=list)
    confidence: float = 0.5


@dataclass
class Campaign:
    """Threat campaign."""
    campaign_id: str
    name: str
    description: str
    actors: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    target_sectors: List[str] = field(default_factory=list)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    status: str = "active"
    threat_level: ThreatLevel = ThreatLevel.HIGH


@dataclass
class ThreatFeed:
    """Threat intelligence feed."""
    feed_id: str
    name: str
    source: FeedSource
    url: Optional[str] = None
    enabled: bool = True
    last_sync: Optional[datetime] = None
    ioc_count: int = 0
    reliability_score: float = 0.5


@dataclass
class EnrichmentResult:
    """Threat enrichment result."""
    enrichment_id: str
    ioc_id: str
    enriched_data: Dict[str, Any]
    providers_used: List[str] = field(default_factory=list)
    enriched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ThreatScore:
    """Threat score calculation."""
    score_id: str
    entity_type: str
    entity_value: str
    overall_score: float
    component_scores: Dict[str, float] = field(default_factory=dict)
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuditEvent:
    """Audit event."""
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True