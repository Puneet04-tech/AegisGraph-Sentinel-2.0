"""
Security Risk Quantification Store - Thread-safe storage
"""

from __future__ import annotations

from threading import Lock
from typing import Dict, List, Optional

from .models import (
    RiskQuantification,
    BusinessExposure,
    ScenarioAnalysis,
    InvestmentRecommendation,
    RiskCategory,
    RiskLevel,
)


class RiskStore:
    """Thread-safe storage for risk data."""

    def __init__(self):
        self._lock = Lock()
        self._risks: Dict[str, RiskQuantification] = {}
        self._exposures: Dict[str, BusinessExposure] = {}
        self._scenarios: Dict[str, ScenarioAnalysis] = {}
        self._recommendations: Dict[str, InvestmentRecommendation] = {}

    def store_risk(self, risk: RiskQuantification) -> RiskQuantification:
        with self._lock:
            self._risks[risk.risk_id] = risk
        return risk

    def get_risk(self, risk_id: str) -> Optional[RiskQuantification]:
        return self._risks.get(risk_id)

    def get_risks_by_category(
        self, category: RiskCategory
    ) -> List[RiskQuantification]:
        return [
            r for r in self._risks.values()
            if r.category == category
        ]

    def get_risks_by_level(
        self, level: RiskLevel
    ) -> List[RiskQuantification]:
        return [
            r for r in self._risks.values()
            if r.risk_level == level
        ]

    def get_all_risks(self) -> List[RiskQuantification]:
        return list(self._risks.values())

    def store_exposure(
        self, exposure: BusinessExposure
    ) -> BusinessExposure:
        with self._lock:
            self._exposures[exposure.exposure_id] = exposure
        return exposure

    def get_exposures_by_risk(self, risk_id: str) -> List[BusinessExposure]:
        return [
            e for e in self._exposures.values()
            if e.risk_id == risk_id
        ]

    def store_scenario(
        self, scenario: ScenarioAnalysis
    ) -> ScenarioAnalysis:
        with self._lock:
            self._scenarios[scenario.scenario_id] = scenario
        return scenario

    def get_scenario(self, scenario_id: str) -> Optional[ScenarioAnalysis]:
        return self._scenarios.get(scenario_id)

    def get_all_scenarios(self) -> List[ScenarioAnalysis]:
        return list(self._scenarios.values())

    def store_recommendation(
        self, recommendation: InvestmentRecommendation
    ) -> InvestmentRecommendation:
        with self._lock:
            self._recommendations[recommendation.recommendation_id] = recommendation
        return recommendation

    def get_recommendations(self) -> List[InvestmentRecommendation]:
        return list(self._recommendations.values())

    def get_metrics(self) -> Dict[str, any]:
        risks = list(self._risks.values())
        category_counts: Dict[str, int] = {}

        for risk in risks:
            category_counts[risk.category.value] = (
                category_counts.get(risk.category.value, 0) + 1
            )

        return {
            "total_risks": len(risks),
            "critical_risks": len([
                r for r in risks if r.risk_level == RiskLevel.CRITICAL
            ]),
            "high_risks": len([
                r for r in risks if r.risk_level == RiskLevel.HIGH
            ]),
            "risks_by_category": category_counts,
            "total_financial_exposure": sum(
                r.financial_impact_expected for r in risks
            ),
        }


_risk_store: Optional[RiskStore] = None
_store_lock = Lock()


def get_risk_store() -> RiskStore:
    global _risk_store
    with _store_lock:
        if _risk_store is None:
            _risk_store = RiskStore()
        return _risk_store


def reset_risk_store() -> None:
    global _risk_store
    with _store_lock:
        _risk_store = RiskStore()
