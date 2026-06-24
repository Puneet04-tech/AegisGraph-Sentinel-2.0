from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class DecisionIntelligencePlatformDecisionContextCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    decision_id: str = Field(..., description="decision_id attribute")
    action_taken: str = Field(..., description="action_taken attribute")
    rationales: List[str] = Field(..., description="rationales attribute")
    confidence: float = Field(..., description="confidence attribute")

class DecisionIntelligencePlatformExplainabilityReportCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    report_id: str = Field(..., description="report_id attribute")
    model_name: str = Field(..., description="model_name attribute")
    feature_importances: Dict[str, float] = Field(..., description="feature_importances attribute")
    explanation_text: str = Field(..., description="explanation_text attribute")

class DecisionIntelligencePlatformRiskRecommendationCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    recommendation_id: str = Field(..., description="recommendation_id attribute")
    threat_vector: str = Field(..., description="threat_vector attribute")
    recommended_action: str = Field(..., description="recommended_action attribute")
    risk_score: float = Field(..., description="risk_score attribute")
