"""Threat Strategy Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class ThreatCategory(Enum):
    """Categories of threats"""
    FRAUD = "FRAUD"
    CYBER = "CYBER"
    INSIDER = "INSIDER"
    FINANCIAL_CRIME = "FINANCIAL_CRIME"
    COMPLIANCE = "COMPLIANCE"

class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class StrategyStatus(Enum):
    """Strategy implementation status"""
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"

@dataclass
class ThreatAssessment:
    """Threat landscape assessment"""
    assessment_id: str
    threat_category: ThreatCategory
    threat_level: ThreatLevel
    description: str
    affected_areas: List[str]
    likelihood: float
    impact: float
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "threat_category": self.threat_category.value,
            "threat_level": self.threat_level.value,
            "description": self.description,
            "affected_areas": self.affected_areas,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.likelihood * self.impact,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class DefenseInitiative:
    """Defense initiative within a strategy"""
    initiative_id: str
    name: str
    description: str
    objective: str
    timeline: str
    resources_required: List[str]
    success_criteria: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initiative_id": self.initiative_id,
            "name": self.name,
            "description": self.description,
            "objective": self.objective,
            "timeline": self.timeline,
            "resources_required": self.resources_required,
            "success_criteria": self.success_criteria
        }

@dataclass
class ThreatStrategy:
    """Strategic defense plan"""
    strategy_id: str
    name: str
    description: str
    threat_assessment: ThreatAssessment
    initiatives: List[DefenseInitiative]
    status: StrategyStatus
    timeline_days: int
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "name": self.name,
            "description": self.description,
            "threat_assessment": self.threat_assessment.to_dict(),
            "initiatives": [i.to_dict() for i in self.initiatives],
            "status": self.status.value,
            "timeline_days": self.timeline_days,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class CampaignForecast:
    """Threat campaign forecast"""
    forecast_id: str
    threat_type: str
    prediction: str
    confidence: float
    timeframe_start: datetime
    timeframe_end: datetime
    affected_sectors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "forecast_id": self.forecast_id,
            "threat_type": self.threat_type,
            "prediction": self.prediction,
            "confidence": self.confidence,
            "timeframe_start": self.timeframe_start.isoformat(),
            "timeframe_end": self.timeframe_end.isoformat(),
            "affected_sectors": self.affected_sectors
        }