"""Adversary Emulation Data Models

Pydantic models for adversary profiles, attack campaigns, simulation steps,
and results used throughout the adversary emulation subsystem.
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime


class AdversaryProfile(BaseModel):
    """Profile defining an adversary's tactics and techniques.

    Attributes:
        id: Unique identifier for the profile.
        name: Human-readable adversary name.
        tactics: List of MITRE ATT&CK tactics used by this adversary.
        techniques: List of specific techniques employed by this adversary.
    """
    id: str = Field(..., description="Profile ID")
    name: str = Field(..., description="Adversary Name")
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)


class SimulationStep(BaseModel):
    """A single step within an attack campaign.

    Attributes:
        step_id: Unique identifier for this step.
        tactic: The MITRE ATT&CK tactic this step implements.
        technique: The specific technique used in this step.
        status: Current execution status of the step.
        success: Whether the step actually succeeded (None until evaluated).
        detected: Whether the step was detected by target security controls
            (None until evaluated).
    """
    step_id: str
    tactic: str
    technique: str
    status: str = "PENDING"
    success: Optional[bool] = None
    detected: Optional[bool] = None


class AttackCampaign(BaseModel):
    """A structured attack campaign generated from an adversary profile.

    Attributes:
        id: Unique identifier for the campaign.
        profile_id: Reference to the AdversaryProfile that generated this campaign.
        target_entity: The target system or entity for the campaign.
        steps: Ordered list of SimulationSteps to execute.
        status: Overall campaign status.
    """
    id: str
    profile_id: str
    target_entity: str
    steps: List[SimulationStep] = Field(default_factory=list)
    status: str = "PENDING"


class SimulationResult(BaseModel):
    """Outcome metrics from executing an attack campaign.

    Attributes:
        campaign_id: Reference to the AttackCampaign that was executed.
        success_rate: Fraction of steps that succeeded (0.0 to 1.0).
        detected_steps: Number of steps that were detected by defenses.
        total_steps: Total number of steps in the campaign.
        validated: Whether the results reflect real execution telemetry; False
            when no outcome evaluation was performed.
        timestamp: When the simulation completed.
    """
    campaign_id: str
    success_rate: float
    detected_steps: int
    total_steps: int
    validated: bool = False
    timestamp: datetime
