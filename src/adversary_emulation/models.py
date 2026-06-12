from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime

class AdversaryProfile(BaseModel):
    id: str = Field(..., description="Profile ID")
    name: str = Field(..., description="Adversary Name")
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)

class SimulationStep(BaseModel):
    step_id: str
    tactic: str
    technique: str
    status: str

class AttackCampaign(BaseModel):
    id: str
    profile_id: str
    target_entity: str
    steps: List[SimulationStep] = Field(default_factory=list)
    status: str = "PENDING"

class SimulationResult(BaseModel):
    campaign_id: str
    success_rate: float
    detected_steps: int
    total_steps: int
    timestamp: datetime
