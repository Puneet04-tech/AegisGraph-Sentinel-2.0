"""
Security Risk Quantification Platform - Data Models

Enterprise risk quantification and financial impact analysis.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List
from pydantic import BaseModel, Field
import uuid


class RiskCategory(str, Enum):
    """Risk categories."""
    CYBER = "CYBER"
    FRAUD = "FRAUD"
    COMPLIANCE = "COMPLIANCE"
    INSIDER = "INSIDER"
    OPERATIONAL = "OPERATIONAL"
    REPUTATIONAL = "REPUTATIONAL"
    FINANCIAL = "FINANCIAL"


class RiskLevel(str, Enum):
    """Risk levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


class ImpactType(str, Enum):
    """Impact types."""
    DIRECT_FINANCIAL = "DIRECT_FINANCIAL"
    INDIRECT_FINANCIAL = "INDIRECT_FINANCIAL"
    OPERATIONAL = "OPERATIONAL"
    REGULATORY = "REGULATORY"
    REPUTATIONAL = "REPUTATIONAL"
    LEGAL = "LEGAL"


class RiskQuantification(BaseModel):
    """Risk quantification record."""
    risk_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    category: RiskCategory
    likelihood: float = 0.5
    impact: float = 0.5
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    affected_assets: List[str] = Field(default_factory=list)
    financial_impact_min: float = 0.0
    financial_impact_max: float = 0.0
    financial_impact_expected: float = 0.0
    annualized_loss_expectancy: float = 0.0
    controls: List[str] = Field(default_factory=list)
    mitigation_effectiveness: float = 0.0
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BusinessExposure(BaseModel):
    """Business exposure assessment."""
    exposure_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    risk_id: str
    business_unit: str
    revenue_impact_percentage: float = 0.0
    operational_impact_hours: float = 0.0
    customer_impact_count: int = 0
    data_breach_records: int = 0
    regulatory_fine_exposure: float = 0.0
    legal_liability_exposure: float = 0.0
    reputation_damage_score: float = 0.0
    total_exposure_value: float = 0.0
    assessment_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScenarioAnalysis(BaseModel):
    """Risk scenario analysis."""
    scenario_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    risk_ids: List[str] = Field(default_factory=list)
    probability: float = 0.0
    impact_assessment: Dict[str, float] = Field(default_factory=dict)
    total_financial_impact: float = 0.0
    mitigation_options: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_action: str = ""
    confidence_level: float = 0.0


class InvestmentRecommendation(BaseModel):
    """Security investment recommendation."""
    recommendation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    investment_type: str
    estimated_cost: float = 0.0
    expected_risk_reduction: float = 0.0
    roi: float = 0.0
    priority: RiskLevel = RiskLevel.MEDIUM
    implementation_effort: str = "MEDIUM"
    timeframe_months: int = 3
    metrics: Dict[str, Any] = Field(default_factory=dict)


class RiskMetrics(BaseModel):
    """Risk metrics."""
    total_risks: int = 0
    critical_risks: int = 0
    high_risks: int = 0
    medium_risks: int = 0
    low_risks: int = 0
    total_financial_exposure: float = 0.0
    mean_risk_score: float = 0.0
    annualized_loss_expectancy: float = 0.0
    risks_by_category: Dict[str, int] = Field(default_factory=dict)
    top_risks: List[Dict[str, Any]] = Field(default_factory=list)
