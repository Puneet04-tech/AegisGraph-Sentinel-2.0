"""AML & Anti-Money Laundering Intelligence Engine Models."""
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Any
from pydantic import BaseModel, Field
import uuid

class AMLAlertType(str, Enum):
    STRUCTURING = "STRUCTURING"
    HIGH_RISK_COUNTRY = "HIGH_RISK_COUNTRY"
    UNUSUAL_PATTERN = "UNUSUAL_PATTERN"
    SAR = "SAR"

class AMLTransaction(BaseModel):
    transaction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    account_id: str
    amount: float
    counterparty: str
    country: str
    risk_indicators: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SARReport(BaseModel):
    sar_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    suspicious_activities: List[str] = Field(default_factory=list)
    narrative: str
    filed: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))