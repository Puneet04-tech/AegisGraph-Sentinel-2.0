"""
Threat Intelligence Marketplace - Data Models

Global threat intelligence sharing and marketplace platform.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class FeedType(str, Enum):
    """Intelligence feed types."""
    MALWARE = "MALWARE"
    IP_REPUTATION = "IP_REPUTATION"
    DOMAIN_REPUTATION = "DOMAIN_REPUTATION"
    URL_REPUTATION = "URL_REPUTATION"
    FILE_HASH = "FILE_HASH"
    VULNERABILITY = "VULNERABILITY"
    THREAT_ACTOR = "THREAT_ACTOR"
    CAMPAIGN = "CAMPAIGN"
    YARA_RULES = "YARA_RULES"
    STIX_PATTERNS = "STIX_PATTERNS"


class FeedStatus(str, Enum):
    """Feed status."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"
    PENDING_REVIEW = "PENDING_REVIEW"


class SubscriptionTier(str, Enum):
    """Subscription tiers."""
    FREE = "FREE"
    BASIC = "BASIC"
    PREMIUM = "PREMIUM"
    ENTERPRISE = "ENTERPRISE"


class AccessLevel(str, Enum):
    """Access levels."""
    PUBLIC = "PUBLIC"
    REGISTERED = "REGISTERED"
    SUBSCRIBED = "SUBSCRIBED"
    PREMIUM = "PREMIUM"


class ThreatFeed(BaseModel):
    """Threat intelligence feed."""
    feed_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    feed_type: FeedType
    provider: str
    provider_id: str
    version: str = "1.0"
    status: FeedStatus = FeedStatus.ACTIVE
    access_level: AccessLevel = AccessLevel.PUBLIC
    subscription_tier: SubscriptionTier = SubscriptionTier.FREE
    indicators_count: int = 0
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    refresh_interval_minutes: int = 60
    coverage: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    certifications: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FeedSubscription(BaseModel):
    """Feed subscription."""
    subscription_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    feed_id: str
    subscriber_id: str
    tier: SubscriptionTier = SubscriptionTier.FREE
    status: str = "ACTIVE"
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    auto_renew: bool = True


class Dataset(BaseModel):
    """Intelligence dataset."""
    dataset_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    provider: str
    provider_id: str
    version: str = "1.0"
    format_type: str = "JSON"
    size_bytes: int = 0
    record_count: int = 0
    access_level: AccessLevel = AccessLevel.SUBSCRIBED
    price_usd: float = 0.0
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FeedQuality(BaseModel):
    """Feed quality metrics."""
    feed_id: str
    accuracy_score: float = 0.0
    freshness_score: float = 0.0
    coverage_score: float = 0.0
    reliability_score: float = 0.0
    overall_score: float = 0.0
    total_ratings: int = 0
    average_rating: float = 0.0
    false_positive_rate: float = 0.0
    last_evaluated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MarketplaceMetrics(BaseModel):
    """Marketplace metrics."""
    total_feeds: int = 0
    active_feeds: int = 0
    total_subscribers: int = 0
    total_datasets: int = 0
    feeds_by_type: Dict[str, int] = Field(default_factory=dict)
    top_rated_feeds: List[Dict[str, Any]] = Field(default_factory=list)
    recent_additions: List[str] = Field(default_factory=list)


class GovernancePolicy(BaseModel):
    """Marketplace governance policy."""
    policy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    policy_type: str
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    enforcement_level: str = "ADVISORY"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
