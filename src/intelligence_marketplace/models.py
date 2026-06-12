"""
Security Intelligence Data Marketplace Models
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class ListingType(Enum):
    DATASET = "DATASET"
    MODEL = "MODEL"
    THREAT_FEED = "THREAT_FEED"
    RULE_SET = "RULE_SET"
    PLAYBOOK = "PLAYBOOK"


class ListingStatus(Enum):
    DRAFT = "DRAFT"
    PUBLISHED = "PUBLISHED"
    ARCHIVED = "ARCHIVED"
    SUSPENDED = "SUSPENDED"


class AccessType(Enum):
    FREE = "FREE"
    PAID = "PAID"
    SUBSCRIPTION = "SUBSCRIPTION"
    ENTERPRISE = "ENTERPRISE"


class SubscriptionTier(Enum):
    FREE = "FREE"
    STANDARD = "STANDARD"
    PREMIUM = "PREMIUM"
    ENTERPRISE = "ENTERPRISE"


@dataclass
class MarketplaceListing:
    listing_id: str
    name: str
    description: str
    listing_type: ListingType
    publisher_id: str
    status: ListingStatus = ListingStatus.DRAFT
    access_type: AccessType = AccessType.FREE
    price: float = 0.0
    tags: List[str] = field(default_factory=list)
    downloads: int = 0
    rating: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "listing_id": self.listing_id,
            "name": self.name,
            "description": self.description,
            "listing_type": self.listing_type.value,
            "publisher_id": self.publisher_id,
            "status": self.status.value,
            "access_type": self.access_type.value,
            "price": self.price,
            "tags": self.tags,
            "downloads": self.downloads,
            "rating": self.rating,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class Subscription:
    subscription_id: str
    listing_id: str
    subscriber_id: str
    tier: SubscriptionTier
    status: str = "ACTIVE"
    subscribed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "subscription_id": self.subscription_id,
            "listing_id": self.listing_id,
            "subscriber_id": self.subscriber_id,
            "tier": self.tier.value,
            "status": self.status,
            "subscribed_at": self.subscribed_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


@dataclass
class Dataset:
    dataset_id: str
    listing_id: str
    name: str
    size: int
    format: str
    features: List[str]
    labels: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "listing_id": self.listing_id,
            "name": self.name,
            "size": self.size,
            "format": self.format,
            "features": self.features,
            "labels": self.labels,
        }


@dataclass
class ThreatFeed:
    feed_id: str
    listing_id: str
    name: str
    feed_type: str
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "listing_id": self.listing_id,
            "name": self.name,
            "feed_type": self.feed_type,
            "indicators": self.indicators,
        }