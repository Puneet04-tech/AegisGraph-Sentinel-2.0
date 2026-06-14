"""Autonomous Fraud Prevention Models"""
from __future__ import annotations
from datetime import datetime, timezone  # noqa: F401
from typing import Any, Dict, List, Optional  # noqa: F401
from pydantic import BaseModel, Field
import uuid


class FraudAlert(BaseModel):
    """Fraud alert."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    transaction_id: str
    risk_score: float = 0.0
    reason: str
    status: str = "OPEN"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PreventionRule(BaseModel):
    """Prevention rule."""
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    condition: Dict[str, Any] = {}
    action: str
    enabled: bool = True


class BlockedTransaction(BaseModel):
    """Blocked transaction."""
    block_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    transaction_id: str
    reason: str
    blocked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FraudMetrics(BaseModel):
    """Fraud prevention metrics."""
    total_alerts: int = 0
    blocked_transactions: int = 0
    prevented_amount: float = 0.0
