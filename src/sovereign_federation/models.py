"""Sovereign Federation Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class FederationRole(Enum):
    """Organization's role in federation"""
    SOVEREIGN = "SOVEREIGN"  # Full control, data origin
    GATEWAY = "GATEWAY"       # Regional hub
    PARTICIPANT = "PARTICIPANT"  # Standard participant

class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    TOP_SECRET = "TOP_SECRET"

class ComplianceStatus(Enum):
    """Compliance verification status"""
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"

@dataclass
class NationalEntity:
    """National intelligence entity"""
    entity_id: str
    name: str
    country_code: str
    entity_type: str
    federation_role: FederationRole
    verified: bool = False
    trust_score: float = 0.5
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "name": self.name,
            "country_code": self.country_code,
            "entity_type": self.entity_type,
            "federation_role": self.federation_role.value,
            "verified": self.verified,
            "trust_score": self.trust_score,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class GovernancePolicy:
    """Sovereignty governance policy"""
    policy_id: str
    name: str
    description: str
    country_code: str
    rules: List[Dict[str, Any]]
    compliance_required: bool = True
    enforcement_level: str = "MANDATORY"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "country_code": self.country_code,
            "rules": self.rules,
            "compliance_required": self.compliance_required,
            "enforcement_level": self.enforcement_level
        }

@dataclass
class IntelligenceShare:
    """Cross-border intelligence share record"""
    share_id: str
    source_entity_id: str
    target_entity_id: str
    data_classification: DataClassification
    content_summary: str
    status: str = "PENDING"
    approved_by: Optional[str] = None
    shared_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "share_id": self.share_id,
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "data_classification": self.data_classification.value,
            "content_summary": self.content_summary,
            "status": self.status,
            "approved_by": self.approved_by,
            "shared_at": self.shared_at.isoformat() if self.shared_at else None
        }

@dataclass
class ComplianceRecord:
    """Compliance verification record"""
    record_id: str
    entity_id: str
    policy_id: str
    status: ComplianceStatus
    verified_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "entity_id": self.entity_id,
            "policy_id": self.policy_id,
            "status": self.status.value,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "details": self.details
        }