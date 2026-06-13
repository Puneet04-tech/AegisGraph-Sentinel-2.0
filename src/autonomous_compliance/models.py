"""Autonomous Regulatory Compliance Agent Models."""
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Any
from pydantic import BaseModel, Field
import uuid

class RegulationType(str, Enum):
    KYC = "KYC"
    AML = "AML"
    GDPR = "GDPR"
    SOX = "SOX"

class ComplianceTask(BaseModel):
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    regulation: RegulationType
    description: str
    status: str = "PENDING"
    priority: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class PolicyEnforcement(BaseModel):
    enforcement_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_name: str
    regulation: RegulationType
    action_taken: str
    automated: bool = True
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))