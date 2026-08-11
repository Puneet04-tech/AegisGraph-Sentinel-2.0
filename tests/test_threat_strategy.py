"""Unit tests for the threat strategy subsystem.

Covers ``src.threat_strategy``: ``StrategyPlanner``, ``StrategySimulator``
and the strategy data models.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.threat_strategy.models import (
    CampaignForecast,
    DefenseInitiative,
    StrategyStatus,
    ThreatAssessment,
    ThreatCategory,
    ThreatLevel,
    ThreatStrategy,
)
from src.threat_strategy.planner import StrategyPlanner
from src.threat_strategy.simulator import StrategySimulator


@pytest.fixture
def planner() -> StrategyPlanner:
    return StrategyPlanner()


@pytest.fixture
def simulator() -> StrategySimulator:
    return StrategySimulator()


def _create_strategy(planner: StrategyPlanner, category=ThreatCategory.FRAUD) -> ThreatStrategy:
    return planner.create_strategy(
        name="Q4 Fraud Defense",
        description="Reduce fraud losses",
        threat_category=category,
        threat_level=ThreatLevel.HIGH,
        threat_description="Increased fraud activity",
        affected_areas=["Payments", "Accounts"],
        likelihood=0.8,
        impact=0.9,
        timeline_days=60,
    )


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_enum_values(self):
        assert ThreatCategory.CYBER.value == "CYBER"
        assert ThreatLevel.CRITICAL.value == "CRITICAL"
        assert StrategyStatus.APPROVED.value == "APPROVED"

    def test_assessment_to_dict_with_risk_score(self):
        assessment = ThreatAssessment(
            assessment_id="a1", threat_category=ThreatCategory.FRAUD,
            threat_level=ThreatLevel.HIGH, description="d",
            affected_areas=["Payments"], likelihood=0.8, impact=0.5,
        )
        data = assessment.to_dict()
        assert data["risk_score"] == 0.4

    def test_initiative_to_dict(self):
        initiative = DefenseInitiative(
            initiative_id="i1", name="n", description="d", objective="o",
            timeline="30 days", resources_required=["ML"], success_criteria=["fraud < 0.5%"],
        )
        assert initiative.to_dict()["success_criteria"] == ["fraud < 0.5%"]

    def test_strategy_to_dict(self):
        assessment = ThreatAssessment(
            assessment_id="a1", threat_category=ThreatCategory.FRAUD, threat_level=ThreatLevel.HIGH,
            description="d", affected_areas=["x"], likelihood=0.5, impact=0.5,
        )
        strategy = ThreatStrategy(
            strategy_id="s1", name="n", description="d", threat_assessment=assessment,
            initiatives=[], status=StrategyStatus.DRAFT, timeline_days=90,
        )
        data = strategy.to_dict()
        assert data["status"] == "DRAFT"
        assert data["threat_assessment"]["risk_score"] == 0.25

    def test_forecast_to_dict(self):
        forecast = CampaignForecast(
            forecast_id="f1", threat_type="FRAUD", prediction="p", confidence=0.8,
            timeframe_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            timeframe_end=datetime(2026, 2, 1, tzinfo=timezone.utc),
            affected_sectors=["Banking"],
        )
        assert forecast.to_dict()["threat_type"] == "FRAUD"


# ---------------------------------------------------------------------------
# StrategyPlanner
# ---------------------------------------------------------------------------


class TestPlanner:
    def test_initiative_templates(self, planner):
        assert ThreatCategory.FRAUD in planner.initiative_templates
        assert ThreatCategory.CYBER in planner.initiative_templates
        assert len(planner.initiative_templates[ThreatCategory.FRAUD]) == 2

    def test_create_strategy(self, planner):
        strategy = _create_strategy(planner)

        assert strategy.status == StrategyStatus.DRAFT
        assert strategy.threat_assessment.likelihood == 0.8
        assert len(strategy.initiatives) == 2  # FRAUD templates
        assert planner.get_strategy(strategy.strategy_id) is strategy

    def test_create_strategy_no_templates_for_unknown_category(self, planner):
        strategy = _create_strategy(planner, category=ThreatCategory.COMPLIANCE)
        assert strategy.initiatives == []

    def test_get_all_strategies(self, planner):
        _create_strategy(planner)
        _create_strategy(planner, category=ThreatCategory.CYBER)
        assert len(planner.get_all_strategies()) == 2
        assert planner.get_strategy("missing") is None

    def test_approve_strategy(self, planner):
        strategy = _create_strategy(planner)

        assert planner.approve_strategy(strategy.strategy_id).status == StrategyStatus.APPROVED
        assert planner.approve_strategy("missing") is None

    def test_update_strategy_status(self, planner):
        strategy = _create_strategy(planner)

        planner.update_strategy_status(strategy.strategy_id, StrategyStatus.IN_PROGRESS)
        assert strategy.status == StrategyStatus.IN_PROGRESS
        assert planner.update_strategy_status("missing", StrategyStatus.COMPLETED) is None

    def test_generate_roadmap(self, planner):
        strategy = _create_strategy(planner, category=ThreatCategory.CYBER)

        roadmap = planner.generate_roadmap(strategy.strategy_id)

        assert roadmap["total_days"] == 60
        assert len(roadmap["phases"]) == 2
        assert roadmap["phases"][0]["initiative"] == "Zero Trust Architecture"
        assert "resources" in roadmap["phases"][0]

    def test_generate_roadmap_missing(self, planner):
        assert planner.generate_roadmap("missing")["error"] == "Strategy not found"


# ---------------------------------------------------------------------------
# StrategySimulator
# ---------------------------------------------------------------------------


class TestSimulator:
    def test_scenario_initialization(self, simulator):
        scenario_ids = {s["scenario_id"] for s in simulator.threat_scenarios}
        assert {"apt-attack", "fraud-campaign", "insider-threat"} <= scenario_ids

    def test_simulate_unknown_scenario(self, simulator):
        result = simulator.simulate_scenario("unknown", ["SIEM"])
        assert result["error"] == "Scenario not found"

    def test_simulate_defense_math(self, simulator, monkeypatch):
        monkeypatch.setattr("random.random", lambda: 0.99)  # nothing detected
        result = simulator.simulate_scenario("apt-attack", ["SIEM", "MFA", "EDR"])

        assert result["scenario"] == "APT Attack Simulation"
        assert result["defense_score"] == pytest.approx(0.45)  # 3 * 0.15
        assert result["attack_success_probability"] == pytest.approx(0.75 * 0.55)
        assert result["overall_detection_rate"] <= 0.99
        assert len(result["steps_survived"]) == len(result["steps_detected"]) + 5
        assert result["simulation_id"] in simulator.simulations

    def test_detection_boost_capped(self, simulator, monkeypatch):
        monkeypatch.setattr("random.random", lambda: 0.99)
        result = simulator.simulate_scenario("apt-attack", ["SIEM"] * 5)

        assert result["defense_score"] == 0.75
        # 0.4 base detection + min(0.375, 0.4) boost = 0.775
        assert result["overall_detection_rate"] == 0.4 + min(0.75 * 0.5, 0.4)

    def test_calculate_risk_thresholds(self, simulator):
        assert simulator._calculate_risk(0.9, 0.0) == "CRITICAL"
        assert simulator._calculate_risk(0.5, 0.3) == "HIGH"
        assert simulator._calculate_risk(0.4, 0.5) == "MEDIUM"
        assert simulator._calculate_risk(0.1, 0.5) == "LOW"

    def test_recommendations_for_gaps(self, simulator):
        recs = simulator._generate_recommendations(
            {"scenario_id": "apt-attack", "name": "APT"}, ["EDR"]
        )
        joined = " ".join(recs)
        assert "Add more defense layers" in joined
        assert "SIEM" in joined
        assert "multi-factor" in joined
        assert "encryption" in joined

    def test_recommendations_scenario_specific(self, simulator):
        apt = simulator._generate_recommendations({"scenario_id": "apt-attack"}, ["SIEM", "MFA", "EDR", "encryption"])
        fraud = simulator._generate_recommendations({"scenario_id": "fraud-campaign"}, ["SIEM", "MFA", "EDR", "encryption"])

        assert any("endpoint detection" in r for r in apt)
        assert any("fraud scoring" in r for r in fraud)

    def test_recommendations_adequate_fallback(self, simulator):
        recs = simulator._generate_recommendations(
            {"scenario_id": "insider-threat"}, ["SIEM", "MFA", "encryption", "EDR", "segmentation"]
        )
        assert recs == ["Current defenses are adequate"]

    def test_forecast_campaign(self, simulator, monkeypatch):
        monkeypatch.setattr("random.random", lambda: 0.5)
        monkeypatch.setattr("random.sample", lambda seq, k: seq[:k])
        monkeypatch.setattr("random.randint", lambda a, b: 2)

        forecast = simulator.forecast_campaign("FRAUD", timeframe_days=30)

        assert forecast.threat_type == "FRAUD"
        assert "account takeover" in forecast.prediction
        assert forecast.confidence == pytest.approx(0.8)
        assert (forecast.timeframe_end - forecast.timeframe_start).days == 30
        assert len(forecast.affected_sectors) == 2

    def test_forecast_unknown_type_fallback(self, simulator, monkeypatch):
        monkeypatch.setattr("random.random", lambda: 0.0)
        monkeypatch.setattr("random.sample", lambda seq, k: seq[:k])
        monkeypatch.setattr("random.randint", lambda a, b: 2)

        forecast = simulator.forecast_campaign("UNKNOWN")
        assert forecast.prediction == "General threat activity"

    def test_simulation_history(self, simulator, monkeypatch):
        monkeypatch.setattr("random.random", lambda: 0.99)
        simulator.simulate_scenario("apt-attack", ["SIEM"])
        simulator.simulate_scenario("fraud-campaign", ["SIEM", "MFA"])

        assert len(simulator.get_simulation_history()) == 2
