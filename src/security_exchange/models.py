"""Security Exchange Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class OrganizationType(Enum):
    """Types of organizations in the exchange"""
    FINANCIAL_INSTITUTION = "FINANCIAL_INSTITUTION"
    GOVERNMENT = "GOVERNMENT"
    TELECOM = "TELECOM"
    SECURITY_PROVIDER = "SECURITY_PROVIDER"
    ENTERPRISE = "ENTERPRISE"

class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

class ShareStatus(Enum):
    """Intelligence sharing status"""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"

@dataclass
class ExchangePartner:
    """Exchange network partner"""
    partner_id: str
    name: str
    organization_type: OrganizationType
    country: str
    verified: bool
    trust_score: float
    data_classification: str = "INTERNAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "partner_id": self.partner_id,
            "name": self.name,
            "organization_type": self.organization_type.value,
            "country": self.country,
            "verified": self.verified,
            "trust_score": self.trust_score,
            "data_classification": self.data_classification
        }

@dataclass
class SharedIntelligence:
    """Shared intelligence record"""
    share_id: str
    title: str
    description: str
    intelligence_type: str
    from_partner: str
    to_partners: List[str]
    classification: DataClassification
    status: ShareStatus
    threat_indicators: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "share_id": self.share_id,
            "title": self.title,
            "description": self.description,
            "intelligence_type": self.intelligence_type,
            "from_partner": self.from_partner,
            "to_partners": self.to_partners,
            "classification": self.classification.value,
            "status": self.status.value,
            "threat_indicators": self.threat_indicators,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None
        }

@dataclass
class DataGovernanceRule:
    """Data governance rule for exchange"""
    rule_id: str
    name: str
    description: str
    classification_required: DataClassification
    partners_allowed: List[str]
    retention_days: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "classification_required": self.classification_required.value,
            "partners_allowed": self.partners_allowed,
            "retention_days": self.retention_days
        }