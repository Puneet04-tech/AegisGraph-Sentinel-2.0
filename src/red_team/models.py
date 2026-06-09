"""
AI Red Team & Adversarial Fraud Simulator Models.

Data models for fraud attack simulation and adversarial testing.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class AttackType(str, Enum):
    """Attack types."""
    ADVERSARIAL_PERTURBATION = "ADVERSARIAL_PERTURBATION"
    DATA_POISONING = "DATA_POISONING"
    MODEL_INVERSION = "MODEL_INVERSION"
    EVASION = "EVASION"
    EXTRACTIVE_ATTACK = "EXTRACTIVE_ATTACK"


class AttackResult(BaseModel):
    """Attack result."""
    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    attack_type: AttackType
    target_model: str
    success: bool
    evasion_rate: float
    detection_avoided: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CampaignResult(BaseModel):
    """Red team campaign result."""
    campaign_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str
    attack_results: List[AttackResult] = Field(default_factory=list)
    overall_success_rate: float
    vulnerabilities_found: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AdversarialSample(BaseModel):
    """Adversarial sample."""
    sample_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    original_features: Dict[str, float]
    perturbed_features: Dict[str, float]
    perturbation_magnitude: float
    attack_type: AttackType
    evaded_detection: bool