"""
Cyber-Fraud Fusion Center Models.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Any
from pydantic import BaseModel, Field
import uuid

class CorrelationType(str, Enum):
    CYBER_TO_FRAUD = "CYBER_TO_FRAUD"
    FRAUD_TO_CYBER = "FRAUD_TO_CYBER"
    BIDIRECTIONAL = "BIDIRECTIONAL"

class FusionEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    source_domain: str  # cyber or fraud
    correlation_score: float
    related_events: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UnifiedIntel(BaseModel):
    intel_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    threat_type: str
    iocs: List[str] = Field(default_factory=list)
    risk_score: float
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))