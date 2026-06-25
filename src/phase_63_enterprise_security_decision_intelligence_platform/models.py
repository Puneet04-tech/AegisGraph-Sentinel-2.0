from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class DecisionIntelligencePlatformDecisionContext:
    record_id: str
    tenant_id: str
    decision_id: str
    action_taken: str
    rationales: List[str]
    confidence: float
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class DecisionIntelligencePlatformExplainabilityReport:
    record_id: str
    tenant_id: str
    report_id: str
    model_name: str
    feature_importances: Dict[str, float]
    explanation_text: str
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class DecisionIntelligencePlatformRiskRecommendation:
    record_id: str
    tenant_id: str
    recommendation_id: str
    threat_vector: str
    recommended_action: str
    risk_score: float
    created_at: datetime = field(default_factory=datetime.utcnow)
