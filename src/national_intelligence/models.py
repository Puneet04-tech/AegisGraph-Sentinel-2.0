"""National Fraud Intelligence Grid Models."""
from datetime import datetime, timezone
from typing import Dict, List, Any
from pydantic import BaseModel, Field
import uuid

class NationalIntel(BaseModel):
    intel_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    threat_category: str
    description: str
    affected_regions: List[str] = Field(default_factory=list)
    severity: str
    shared_by: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class FederationNode(BaseModel):
    node_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    institution_name: str
    node_type: str
    connected: bool = True