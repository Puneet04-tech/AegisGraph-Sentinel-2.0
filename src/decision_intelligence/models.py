"""
Autonomous Security Decision Engine - Data Models

AI-driven decision intelligence for AegisGraph Sentinel 2.0.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class DecisionType(str, Enum):
    """Decision types."""
    RECOMMENDATION = "RECOMMENDATION"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    MITIGATION = "MITIGATION"
    RESPONSE = "RESPONSE"
    GOVERNANCE = "GOVERNANCE"
    PRIORITIZATION = "PRIORITIZATION"


class DecisionPriority(str, Enum):
    """Decision priorities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DecisionStatus(str, Enum):
    """Decision status."""
    PENDING = "PENDING"
    RECOMMENDED = "RECOMMENDED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    IMPLEMENTED = "IMPLEMENTED"


class SecurityRecommendation(BaseModel):
    """Security recommendation."""
    recommendation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    decision_type: DecisionType
    priority: DecisionPriority = DecisionPriority.MEDIUM
    status: DecisionStatus = DecisionStatus.PENDING
    confidence: float = 0.0
    risk_score: Optional[float] = None
    impacted_assets: List[str] = Field(default_factory=list)
    expected_outcome: str = ""
    implementation_steps: List[str] = Field(default_factory=list)
    estimated_effort: str = "MEDIUM"
    business_impact: str = ""
    context: Dict[str, Any] = Field(default_factory=dict)
    reasoning: str = ""
    alternatives: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    decided_at: Optional[datetime] = None


class MitigationAction(BaseModel):
    """Mitigation action."""
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    recommendation_id: str
    title: str
    description: str
    action_type: str
    priority: DecisionPriority
    status: str = "PENDING"
    assigned_to: Optional[str] = None
    estimated_duration: str = ""
    risk_reduction: float = 0.0
    implementation_notes: List[str] = Field(default_factory=list)


class RiskDecision(BaseModel):
    """Risk-based decision."""
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    context: str
    risk_factors: Dict[str, float] = Field(default_factory=dict)
    decision: str
    reasoning: str = ""
    confidence: float = 0.0
    alternatives_considered: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExplainabilityRecord(BaseModel):
    """Explainability record for decisions."""
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision_id: str
    explanation: str
    factors: List[Dict[str, Any]] = Field(default_factory=list)
    confidence_breakdown: Dict[str, float] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)


class GovernanceDecision(BaseModel):
    """Governance decision."""
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: Optional[str] = None
    title: str
    description: str
    decision_type: DecisionType
    rationale: str = ""
    approved_by: Optional[str] = None
    compliance_impact: str = ""
    audit_trail: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DecisionMetrics(BaseModel):
    """Decision metrics."""
    total_decisions: int = 0
    recommendations_generated: int = 0
    recommendations_approved: int = 0
    average_confidence: float = 0.0
    decisions_by_type: Dict[str, int] = Field(default_factory=dict)
    decisions_by_priority: Dict[str, int] = Field(default_factory=dict)
    top_recommendations: List[Dict[str, Any]] = Field(default_factory=list)
