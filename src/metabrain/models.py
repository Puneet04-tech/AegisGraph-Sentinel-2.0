"""MetaBrain Models for Enterprise Security Intelligence"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class IntelligenceLevel(Enum):
    """Intelligence processing levels"""
    TACTICAL = "TACTICAL"
    OPERATIONAL = "OPERATIONAL"
    STRATEGIC = "STRATEGIC"

class AnalysisType(Enum):
    """Types of security analysis"""
    FRAUD = "FRAUD"
    CYBER_THREAT = "CYBER_THREAT"
    COMPLIANCE = "COMPLIANCE"
    INSIDER_RISK = "INSIDER_RISK"
    FINANCIAL_CRIME = "FINANCIAL_CRIME"
    OPERATIONAL_RISK = "OPERATIONAL_RISK"

@dataclass
class IntelligenceSignal:
    """Cross-domain intelligence signal"""
    signal_id: str
    signal_type: AnalysisType
    source_module: str
    severity: str
    description: str
    confidence: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type.value,
            "source_module": self.source_module,
            "severity": self.severity,
            "description": self.description,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "tags": self.tags
        }

@dataclass
class StrategicInsight:
    """Strategic insight from MetaBrain analysis"""
    insight_id: str
    title: str
    description: str
    intelligence_level: IntelligenceLevel
    affected_domains: List[str]
    recommended_actions: List[str]
    priority: int
    confidence: float
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "insight_id": self.insight_id,
            "title": self.title,
            "description": self.description,
            "intelligence_level": self.intelligence_level.value,
            "affected_domains": self.affected_domains,
            "recommended_actions": self.recommended_actions,
            "priority": self.priority,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class StrategicRecommendation:
    """Autonomous recommendation from MetaBrain"""
    recommendation_id: str
    title: str
    description: str
    target_domain: str
    action_type: str
    estimated_impact: str
    confidence: float
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "title": self.title,
            "description": self.description,
            "target_domain": self.target_domain,
            "action_type": self.action_type,
            "estimated_impact": self.estimated_impact,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class Forecast:
    """Security forecast from MetaBrain"""
    forecast_id: str
    forecast_type: str
    prediction: str
    timeframe: str
    confidence: float
    affected_sectors: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "forecast_id": self.forecast_id,
            "forecast_type": self.forecast_type,
            "prediction": self.prediction,
            "timeframe": self.timeframe,
            "confidence": self.confidence,
            "affected_sectors": self.affected_sectors,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class Strategy:
    """Defense strategy from MetaBrain"""
    strategy_id: str
    name: str
    description: str
    objectives: List[str]
    phases: List[str]
    success_metrics: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "name": self.name,
            "description": self.description,
            "objectives": self.objectives,
            "phases": self.phases,
            "success_metrics": self.success_metrics,
            "created_at": self.created_at.isoformat()
        }