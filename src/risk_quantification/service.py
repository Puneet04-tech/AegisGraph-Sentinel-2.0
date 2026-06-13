"""
Security Risk Quantification Service - Core business logic
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import (
    RiskQuantification,
    BusinessExposure,
    ScenarioAnalysis,
    InvestmentRecommendation,
    RiskMetrics,
    RiskCategory,
    RiskLevel,
)
from .store import get_risk_store, RiskStore, reset_risk_store


class RiskService:
    """Core risk quantification service."""

    def __init__(self, store: Optional[RiskStore] = None):
        self._store = store or get_risk_store()

    def quantify_risk(
        self,
        name: str,
        description: str,
        category: RiskCategory,
        likelihood: float = 0.5,
        impact: float = 0.5,
        **kwargs: Any,
    ) -> RiskQuantification:
        """Quantify a risk."""
        risk_score = likelihood * impact
        risk_level = self._calculate_risk_level(risk_score)
        ale = risk_score * kwargs.get("exposure_value", 1000000)

        risk = RiskQuantification(
            name=name,
            description=description,
            category=category,
            likelihood=likelihood,
            impact=impact,
            risk_score=risk_score,
            risk_level=risk_level,
            annualized_loss_expectancy=ale,
            **kwargs,
        )
        self._store.store_risk(risk)
        return risk

    def _calculate_risk_level(self, risk_score: float) -> RiskLevel:
        """Calculate risk level from score."""
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.2:
            return RiskLevel.LOW
        return RiskLevel.MINIMAL

    def get_risk(self, risk_id: str) -> Optional[RiskQuantification]:
        """Get risk by ID."""
        return self._store.get_risk(risk_id)

    def get_risks(
        self,
        category: Optional[RiskCategory] = None,
        level: Optional[RiskLevel] = None,
    ) -> List[RiskQuantification]:
        """Get risks with optional filters."""
        risks = self._store.get_all_risks()

        if category:
            risks = [r for r in risks if r.category == category]
        if level:
            risks = [r for r in risks if r.risk_level == level]

        return risks

    def assess_business_exposure(
        self,
        risk_id: str,
        business_unit: str,
        revenue_impact_percentage: float = 0.0,
        **kwargs: Any,
    ) -> BusinessExposure:
        """Assess business exposure for a risk."""
        exposure = BusinessExposure(
            risk_id=risk_id,
            business_unit=business_unit,
            revenue_impact_percentage=revenue_impact_percentage,
            **kwargs,
        )
        self._store.store_exposure(exposure)
        return exposure

    def analyze_scenario(
        self,
        name: str,
        description: str,
        risk_ids: List[str],
        **kwargs: Any,
    ) -> ScenarioAnalysis:
        """Analyze a risk scenario."""
        total_impact = 0.0
        for rid in risk_ids:
            risk = self._store.get_risk(rid)
            if risk:
                total_impact += risk.financial_impact_expected

        scenario = ScenarioAnalysis(
            name=name,
            description=description,
            risk_ids=risk_ids,
            total_financial_impact=total_impact,
            **kwargs,
        )
        self._store.store_scenario(scenario)
        return scenario

    def get_scenarios(self) -> List[ScenarioAnalysis]:
        """Get all scenarios."""
        return self._store.get_all_scenarios()

    def recommend_investment(
        self,
        title: str,
        description: str,
        investment_type: str,
        estimated_cost: float,
        expected_risk_reduction: float,
        **kwargs: Any,
    ) -> InvestmentRecommendation:
        """Recommend a security investment."""
        if estimated_cost > 0:
            roi = expected_risk_reduction / estimated_cost
        else:
            roi = 0.0

        recommendation = InvestmentRecommendation(
            title=title,
            description=description,
            investment_type=investment_type,
            estimated_cost=estimated_cost,
            expected_risk_reduction=expected_risk_reduction,
            roi=roi,
            **kwargs,
        )
        self._store.store_recommendation(recommendation)
        return recommendation

    def get_recommendations(self) -> List[InvestmentRecommendation]:
        """Get all investment recommendations."""
        return self._store.get_recommendations()

    def get_metrics(self) -> RiskMetrics:
        """Get risk metrics."""
        risks = self._store.get_all_risks()
        category_counts: Dict[str, int] = {}

        for risk in risks:
            category_counts[risk.category.value] = (
                category_counts.get(risk.category.value, 0) + 1
            )

        top_risks = [
            {"risk_id": r.risk_id, "name": r.name, "score": r.risk_score}
            for r in sorted(risks, key=lambda x: x.risk_score, reverse=True)[:10]
        ]

        return RiskMetrics(
            total_risks=len(risks),
            critical_risks=len([
                r for r in risks if r.risk_level == RiskLevel.CRITICAL
            ]),
            high_risks=len([
                r for r in risks if r.risk_level == RiskLevel.HIGH
            ]),
            medium_risks=len([
                r for r in risks if r.risk_level == RiskLevel.MEDIUM
            ]),
            low_risks=len([
                r for r in risks if r.risk_level == RiskLevel.LOW
            ]),
            total_financial_exposure=sum(
                r.financial_impact_expected for r in risks
            ),
            mean_risk_score=sum(r.risk_score for r in risks) / max(len(risks), 1),
            annualized_loss_expectancy=sum(
                r.annualized_loss_expectancy for r in risks
            ),
            risks_by_category=category_counts,
            top_risks=top_risks,
        )

    def clear(self) -> None:
        """Clear all data."""
        reset_risk_store()


_risk_service: Optional[RiskService] = None


def get_risk_service() -> RiskService:
    global _risk_service
    if _risk_service is None:
        _risk_service = RiskService()
    return _risk_service


def reset_risk_service() -> None:
    global _risk_service
    _risk_service = None
    reset_risk_store()
