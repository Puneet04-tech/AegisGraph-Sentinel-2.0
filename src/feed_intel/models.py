"""Threat Intelligence Feed Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class IOCType(Enum):
    """Indicator of Compromise types"""
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    EMAIL = "EMAIL"
    FILE = "FILE"

class FeedStatus(Enum):
    """Feed status"""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    ERROR = "ERROR"
    MAINTENANCE = "MAINTENANCE"

@dataclass
class ThreatFeed:
    """Threat intelligence feed"""
    feed_id: str
    name: str
    description: str
    feed_type: str
    source_url: str
    status: FeedStatus
    ioc_count: int = 0
    last_updated: Optional[datetime] = None
    reliability_score: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "name": self.name,
            "description": self.description,
            "feed_type": self.feed_type,
            "source_url": self.source_url,
            "status": self.status.value,
            "ioc_count": self.ioc_count,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "reliability_score": self.reliability_score
        }

@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_id: str
    value: str
    ioc_type: IOCType
    feed_id: str
    threat_type: str
    confidence: float
    first_seen: datetime
    last_seen: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_id": self.ioc_id,
            "value": self.value,
            "ioc_type": self.ioc_type.value,
            "feed_id": self.feed_id,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "tags": self.tags,
            "metadata": self.metadata
        }