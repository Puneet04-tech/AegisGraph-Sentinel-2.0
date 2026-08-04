"""Unit tests for the MetaBrain reasoning engine and store.

Covers ``src.metabrain``: ``ReasoningEngine`` and ``MetaBrainStore``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.metabrain.models import (
    AnalysisType,
    Forecast,
    IntelligenceLevel,
    IntelligenceSignal,
    StrategicInsight,
    StrategicRecommendation,
    Strategy,
)
from src.metabrain.reasoning_engine import ReasoningEngine
from src.metabrain.store import MetaBrainStore


def _signal(signal_id="s1", signal_type=AnalysisType.FRAUD, severity="HIGH", confidence=0.8,
            timestamp=None) -> IntelligenceSignal:
    return IntelligenceSignal(
        signal_id=signal_id,
        signal_type=signal_type,
        source_module="fraud_detection",
        severity=severity,
        description="Suspicious activity",
        confidence=confidence,
        timestamp=timestamp or datetime.now(timezone.utc),
    )


@pytest.fixture
def engine() -> ReasoningEngine:
    return ReasoningEngine()


@pytest.fixture
def store() -> MetaBrainStore:
    return MetaBrainStore()


# ---------------------------------------------------------------------------
# ReasoningEngine
# ---------------------------------------------------------------------------


class TestReasoningEngine:
    def test_correlation_rules_initialized(self, engine):
        assert len(engine.correlation_rules) == 3

    def test_add_signal(self, engine):
        signal = _signal()
        assert engine.add_signal(signal) == "s1"
        assert engine.signals["s1"] is signal

    def test_correlate_signals_cross_domain(self, engine):
        engine.add_signal(_signal("s1", AnalysisType.FRAUD, confidence=0.6))
        engine.add_signal(_signal("s2", AnalysisType.CYBER_THREAT, confidence=0.8))

        insights = engine.correlate_signals()

        assert len(insights) == 1
        insight = insights[0]
        assert "Fraud-CTI Correlation" in insight.title
        assert insight.intelligence_level == IntelligenceLevel.OPERATIONAL
        assert insight.confidence == pytest.approx(0.7 * 1.5)
        assert insight.priority == 1

    def test_correlate_single_signal_no_insight(self, engine):
        engine.add_signal(_signal("s1", AnalysisType.FRAUD))

        assert engine.correlate_signals() == []

    def test_correlate_same_domain_meets_rule_threshold(self, engine):
        engine.add_signal(_signal("s1", AnalysisType.FRAUD))
        engine.add_signal(_signal("s2", AnalysisType.FRAUD))

        insights = engine.correlate_signals()
        assert len(insights) == 2  # Fraud-CTI + Financial Crime Pattern rules
        assert sorted(i.confidence for i in insights) == pytest.approx([0.8 * 1.4, 0.8 * 1.5])

    def test_insider_compliance_correlation(self, engine):
        engine.add_signal(_signal("s1", AnalysisType.INSIDER_RISK, confidence=0.5))
        engine.add_signal(_signal("s2", AnalysisType.COMPLIANCE, confidence=0.5))

        insights = engine.correlate_signals()
        assert len(insights) == 1
        assert insights[0].confidence == pytest.approx(0.5 * 1.3)

    def test_analyze_threat_landscape(self, engine):
        engine.add_signal(_signal("s1", severity="CRITICAL"))
        engine.add_signal(_signal("s2", severity="HIGH"))
        engine.add_signal(_signal("s3", AnalysisType.CYBER_THREAT, severity="LOW"))

        stats = engine.analyze_threat_landscape()
        assert stats["total_signals"] == 3
        assert stats["severity_distribution"]["CRITICAL"] == 1
        assert stats["type_distribution"][AnalysisType.FRAUD.value] == 2

    def test_threat_level_thresholds(self, engine):
        assert engine._calculate_threat_level({"CRITICAL": 6}) == "CRITICAL"  # 24
        assert engine._calculate_threat_level({"HIGH": 4}) == "HIGH"  # 12
        assert engine._calculate_threat_level({"MEDIUM": 3}) == "MEDIUM"  # 6
        assert engine._calculate_threat_level({"LOW": 1}) == "LOW"

    def test_insights_by_level(self, engine):
        engine.add_signal(_signal("s1", AnalysisType.FRAUD, confidence=0.6))
        engine.add_signal(_signal("s2", AnalysisType.CYBER_THREAT, confidence=0.6))

        insights = engine.get_insights_by_level(IntelligenceLevel.OPERATIONAL)
        assert len(insights) == 1
        assert engine.get_insights_by_level(IntelligenceLevel.STRATEGIC) == []


# ---------------------------------------------------------------------------
# MetaBrainStore
# ---------------------------------------------------------------------------


class TestMetaBrainStore:
    def test_signal_crud(self, store):
        store.add_signal(_signal())
        assert store.get_signal("s1") is not None
        assert store.get_signal("missing") is None

    def test_signals_most_recent_first_with_limit(self, store):
        old = _signal("old", timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc))
        new = _signal("new", timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc))
        store.add_signal(old)
        store.add_signal(new)

        assert [s.signal_id for s in store.get_all_signals()] == ["new", "old"]
        assert len(store.get_all_signals(limit=1)) == 1

    def test_signals_by_type(self, store):
        store.add_signal(_signal("s1", AnalysisType.FRAUD))
        store.add_signal(_signal("s2", AnalysisType.COMPLIANCE))

        assert len(store.get_signals_by_type("FRAUD")) == 1
        assert len(store.get_signals_by_type("MISSING")) == 0

    def test_insight_crud_and_priority_order(self, store):
        low = StrategicInsight(
            insight_id="low", title="t", description="d", intelligence_level=IntelligenceLevel.TACTICAL,
            affected_domains=["x"], recommended_actions=["a"], priority=2, confidence=0.5,
        )
        high = StrategicInsight(
            insight_id="high", title="t", description="d", intelligence_level=IntelligenceLevel.STRATEGIC,
            affected_domains=["x"], recommended_actions=["a"], priority=1, confidence=0.5,
        )
        store.add_insight(high)
        store.add_insight(low)

        assert store.get_insight("low") is low
        assert store.get_insight("missing") is None
        assert [i.insight_id for i in store.get_all_insights()] == ["high", "low"]

    def test_recommendation_crud(self, store):
        rec = StrategicRecommendation(
            recommendation_id="r1", title="t", description="d", target_domain="FRAUD",
            action_type="mitigate", estimated_impact="high", confidence=0.9,
        )
        store.add_recommendation(rec)
        assert store.get_recommendation("r1") is rec
        assert store.get_all_recommendations() == [rec]

    def test_forecast_and_strategy_crud(self, store):
        forecast = Forecast(
            forecast_id="f1", forecast_type="FRAUD", prediction="p", timeframe="30d",
            confidence=0.7, affected_sectors=["Banking"],
        )
        store.add_forecast(forecast)
        assert store.get_forecast("f1") is forecast
        assert store.get_all_forecasts() == [forecast]

        strategy = Strategy(
            strategy_id="st1", name="n", description="d",
            objectives=["o"], phases=["p"], success_metrics=["m"],
        )
        store.add_strategy(strategy)
        assert store.get_strategy("st1") is strategy
        assert store.get_all_strategies() == [strategy]

    def test_dashboard_data(self, store):
        store.add_signal(_signal())
        store.add_insight(StrategicInsight(
            insight_id="i1", title="t", description="d", intelligence_level=IntelligenceLevel.TACTICAL,
            affected_domains=["x"], recommended_actions=["a"], priority=1, confidence=0.5,
        ))

        data = store.get_dashboard_data()
        assert data["total_signals"] == 1
        assert data["total_insights"] == 1
        assert data["total_recommendations"] == 0

    def test_clear_old_data(self, store):
        store.add_signal(_signal("old", timestamp=datetime.now(timezone.utc) - timedelta(days=60)))
        store.add_signal(_signal("new", timestamp=datetime.now(timezone.utc)))

        store.clear_old_data(days=30)
        assert store.get_signal("old") is None
        assert store.get_signal("new") is not None
