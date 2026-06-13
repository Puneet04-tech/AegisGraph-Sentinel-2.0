"""Trust Intelligence Platform - Data Models"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class TrustScore(BaseModel):
    """Trust score."""
    score_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str
    trust_score: float = 0.5
    confidence: float = 0.0
    factors: Dict[str, float] = Field(default_factory=dict)
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IdentityVerification(BaseModel):
    """Identity verification."""
    verification_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str
    verification_level: str = "BASIC"
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


class ReputationIndex(BaseModel):
    """Reputation index."""
    index_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str
    score: float = 0.0
    history: List[Dict[str, Any]] = Field(default_factory=list)


class TrustPolicy(BaseModel):
    """Trust policy."""
    policy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    min_trust_score: float = 0.5
    action: str
    enabled: bool = True


class TrustMetrics(BaseModel):
    """Trust metrics."""
    total_entities: int = 0
    avg_trust_score: float = 0.0
    verified_entities: int = 0
    high_risk_entities: int = 0
