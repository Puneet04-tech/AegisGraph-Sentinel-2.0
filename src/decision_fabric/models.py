"""
AI Decision Intelligence Fabric Models
Explainable enterprise decision support.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class DecisionType(Enum):
    """Types of decisions."""
    FRAUD_APPROVAL = "FRAUD_APPROVAL"
    THREAT_RESPONSE = "THREAT_RESPONSE"
    AML_ALERT = "AML_ALERT"
    COMPLIANCE_CHECK = "COMPLIANCE_CHECK"
    ACCESS_REQUEST = "ACCESS_REQUEST"
    TRANSACTION_APPROVAL = "TRANSACTION_APPROVAL"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    INVESTIGATION_REVIEW = "INVESTIGATION_REVIEW"


class DecisionStatus(Enum):
    """Decision status."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ESCALATED = "ESCALATED"
    REVIEWED = "REVIEWED"


class DecisionConfidence(Enum):
    """Decision confidence levels."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Decision:
    """A decision made by the system."""
    decision_id: str
    decision_type: DecisionType
    context: Dict[str, Any]
    outcome: str
    status: DecisionStatus = DecisionStatus.PENDING
    confidence: float = 0.5
    confidence_level: DecisionConfidence = DecisionConfidence.MEDIUM
    reasoning: List[str] = field(default_factory=list)
    alternatives: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    decided_by: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "decision_type": self.decision_type.value,
            "context": self.context,
            "outcome": self.outcome,
            "status": self.status.value,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "reasoning": self.reasoning,
            "alternatives": self.alternatives,
            "created_at": self.created_at.isoformat(),
            "decided_by": self.decided_by,
            "metadata": self.metadata,
        }


@dataclass
class DecisionExplanation:
    """Explanation for a decision."""
    explanation_id: str
    decision_id: str
    factors: List[Dict[str, Any]]
    recommendations: List[str]
    risk_factors: List[str]
    mitigation_suggestions: List[str]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "explanation_id": self.explanation_id,
            "decision_id": self.decision_id,
            "factors": self.factors,
            "recommendations": self.recommendations,
            "risk_factors": self.risk_factors,
            "mitigation_suggestions": self.mitigation_suggestions,
            "generated_at": self.generated_at.isoformat(),
        }


@dataclass
class PolicyRule:
    """A policy rule for decisions."""
    rule_id: str
    name: str
    description: str
    decision_type: DecisionType
    conditions: List[Dict[str, Any]]
    actions: List[str]
    priority: int = 0
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "decision_type": self.decision_type.value,
            "conditions": self.conditions,
            "actions": self.actions,
            "priority": self.priority,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class DecisionAudit:
    """Decision audit record."""
    audit_id: str
    decision_id: str
    action: str
    user: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "decision_id": self.decision_id,
            "action": self.action,
            "user": self.user,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }