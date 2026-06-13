"""Autonomous Fraud Prevention Network - Data Models"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Any, Dict
from pydantic import BaseModel, Field
import uuid


class PreventionPolicy(BaseModel):
    """Prevention policy."""
    policy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    policy_type: str
    conditions: List[Dict[str, Any]] = Field(default_factory=list)
    action: str
    enabled: bool = True


class FraudPattern(BaseModel):
    """Fraud pattern."""
    pattern_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    pattern_type: str
    indicators: List[str] = Field(default_factory=list)
    severity: str = "MEDIUM"
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RiskScore(BaseModel):
    """Risk score."""
    score_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str
    score: float = 0.0
    factors: List[str] = Field(default_factory=list)
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BlockRule(BaseModel):
    """Block rule."""
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    pattern_id: str
    threshold: float = 0.8
    duration_minutes: int = 60
    enabled: bool = True


class PreventionEvent(BaseModel):
    """Prevention event."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    entity_id: str
    action_taken: str
    outcome: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PreventionMetrics(BaseModel):
    """Prevention metrics."""
    total_prevented: int = 0
    total_blocked: int = 0
    patterns_learned: int = 0
    policies_active: int = 0
