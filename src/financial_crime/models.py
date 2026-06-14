"""Financial Crime Intelligence Platform Models."""
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Any
from pydantic import BaseModel, Field
import uuid

class CrimeType(str, Enum):
    MONEY_LAUNDERING = "MONEY_LAUNDERING"
    DRUG_TRAFFICKING = "DRUG_TRAFFICKING"
    TERRORIST_FINANCING = "TERRORIST_FINANCING"
    TAX_EVASION = "TAX_EVASION"

class CrimeNetwork(BaseModel):
    network_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    crime_type: CrimeType
    involved_entities: List[str] = Field(default_factory=list)
    risk_score: float
    investigation_status: str = "ACTIVE"

class InvestigationSupport(BaseModel):
    support_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    recommendations: List[str] = Field(default_factory=list)
    risk_assessment: Dict[str, Any] = Field(default_factory=dict)