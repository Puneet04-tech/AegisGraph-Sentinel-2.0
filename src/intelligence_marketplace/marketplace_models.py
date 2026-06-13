"""Intelligence Marketplace Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class AssetType(Enum):
    """Types of intelligence assets"""
    AI_MODEL = "AI_MODEL"
    FRAUD_DETECTOR = "FRAUD_DETECTOR"
    THREAT_FEED = "THREAT_FEED"
    INVESTIGATION_TEMPLATE = "INVESTIGATION_TEMPLATE"
    COMPLIANCE_POLICY = "COMPLIANCE_POLICY"
    GOVERNANCE_FRAMEWORK = "GOVERNANCE_FRAMEWORK"

class AssetStatus(Enum):
    """Asset status"""
    DRAFT = "DRAFT"
    PUBLISHED = "PUBLISHED"
    CERTIFIED = "CERTIFIED"
    DEPRECATED = "DEPRECATED"

class SubscriptionStatus(Enum):
    """Subscription status"""
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"

@dataclass
class IntelligenceAsset:
    """Intelligence asset in the marketplace"""
    asset_id: str
    name: str
    description: str
    asset_type: AssetType
    publisher_id: str
    version: str
    status: AssetStatus
    tags: List[str]
    downloads: int = 0
    rating: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "description": self.description,
            "asset_type": self.asset_type.value,
            "publisher_id": self.publisher_id,
            "version": self.version,
            "status": self.status.value,
            "tags": self.tags,
            "downloads": self.downloads,
            "rating": self.rating,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata
        }

@dataclass
class Subscription:
    """Asset subscription"""
    subscription_id: str
    asset_id: str
    subscriber_id: str
    status: SubscriptionStatus
    start_date: datetime
    end_date: datetime
    price_paid: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subscription_id": self.subscription_id,
            "asset_id": self.asset_id,
            "subscriber_id": self.subscriber_id,
            "status": self.status.value,
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat(),
            "price_paid": self.price_paid
        }

@dataclass
class Publisher:
    """Marketplace publisher"""
    publisher_id: str
    name: str
    description: str
    verified: bool = False
    total_assets: int = 0
    total_subscribers: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "publisher_id": self.publisher_id,
            "name": self.name,
            "description": self.description,
            "verified": self.verified,
            "total_assets": self.total_assets,
            "total_subscribers": self.total_subscribers
        }