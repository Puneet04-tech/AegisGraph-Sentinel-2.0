"""Tests for MetaBrain Planner and RecommendationEngine"""
import pytest
from datetime import datetime, timezone
from uuid import UUID

from src.metabrain.models import (
    AnalysisType,
    IntelligenceLevel,
    StrategicInsight,
    StrategicRecommendation,
    Strategy,
)
from src.metabrain.planner import Planner
from src.metabrain.recommendation_engine import RecommendationEngine


def make_insight(
    insight_id="ins-1",
    title="Phishing campaign",
    description="Credential harvesting via email",
    intelligence_level=IntelligenceLevel.TACTICAL,
    affected_domains=None,
    recommended_actions=None,
    priority=3,
    confidence=0.85,
    created_at=None,
):
    return StrategicInsight(
        insight_id=insight_id,
        title=title,
        description=description,
        intelligence_level=intelligence_level,
        affected_domains=affected_domains or ["payments", "transfers"],
        recommended_actions=recommended_actions or ["Block domain"],
        priority=priority,
        confidence=confidence,
        created_at=created_at if created_at is not None else datetime(2024, 1, 1, 0, 0),
    )


class TestEnums:
    def test_intelligence_level_values(self):
        assert IntelligenceLevel.TACTICAL.value == "TACTICAL"
        assert IntelligenceLevel.OPERATIONAL.value == "OPERATIONAL"
        assert IntelligenceLevel.STRATEGIC.value == "STRATEGIC"

    def test_intelligence_level_members(self):
        assert set(IntelligenceLevel.__members__) == {
            "TACTICAL", "OPERATIONAL", "STRATEGIC"
        }

    def test_analysis_type_values(self):
        assert AnalysisType.FRAUD.value == "FRAUD"
        assert AnalysisType.CYBER_THREAT.value == "CYBER_THREAT"
        assert AnalysisType.COMPLIANCE.value == "COMPLIANCE"
        assert AnalysisType.INSIDER_RISK.value == "INSIDER_RISK"
        assert AnalysisType.FINANCIAL_CRIME.value == "FINANCIAL_CRIME"
        assert AnalysisType.OPERATIONAL_RISK.value == "OPERATIONAL_RISK"


class TestStrategicInsight:
    def test_to_dict(self):
        created = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
        insight = make_insight(
            insight_id="ins-1",
            title="Phishing campaign",
            description="Credential harvesting",
            intelligence_level=IntelligenceLevel.STRATEGIC,
            affected_domains=["payments", "email"],
            recommended_actions=["Block domain", "Notify users"],
            priority=5,
            confidence=0.7,
            created_at=created,
        )
        data = insight.to_dict()
        assert data == {
            "insight_id": "ins-1",
            "title": "Phishing campaign",
            "description": "Credential harvesting",
            "intelligence_level": "STRATEGIC",
            "affected_domains": ["payments", "email"],
            "recommended_actions": ["Block domain", "Notify users"],
            "priority": 5,
            "confidence": 0.7,
            "created_at": "2024-01-01T12:00:00+00:00",
        }

    def test_to_dict_serializes_enum_level(self):
        data = make_insight(intelligence_level=IntelligenceLevel.TACTICAL).to_dict()
        assert data["intelligence_level"] == "TACTICAL"


class TestStrategicRecommendation:
    def test_to_dict(self):
        created = datetime(2024, 2, 2, 8, 30, tzinfo=timezone.utc)
        rec = StrategicRecommendation(
            recommendation_id="rec-1",
            title="Action Required: Phishing",
            description="Conduct deep investigation on payments, transfers",
            target_domain="payments, transfers",
            action_type="INVESTIGATE",
            estimated_impact="Medium",
            confidence=0.9,
            created_at=created,
        )
        assert rec.to_dict() == {
            "recommendation_id": "rec-1",
            "title": "Action Required: Phishing",
            "description": "Conduct deep investigation on payments, transfers",
            "target_domain": "payments, transfers",
            "action_type": "INVESTIGATE",
            "estimated_impact": "Medium",
            "confidence": 0.9,
            "created_at": "2024-02-02T08:30:00+00:00",
        }


class TestStrategy:
    def test_to_dict(self):
        created = datetime(2024, 3, 3, 9, 45, tzinfo=timezone.utc)
        strategy = Strategy(
            strategy_id="strat-1",
            name="Q4 Fraud Defense",
            description="Plan",
            objectives=["Reduce losses"],
            phases=["Phase 1"],
            success_metrics=["Fraud rate"],
            created_at=created,
        )
        assert strategy.to_dict() == {
            "strategy_id": "strat-1",
            "name": "Q4 Fraud Defense",
            "description": "Plan",
            "objectives": ["Reduce losses"],
            "phases": ["Phase 1"],
            "success_metrics": ["Fraud rate"],
            "created_at": "2024-03-03T09:45:00+00:00",
        }


class TestPlannerInit:
    def test_init_templates(self):
        planner = Planner()
        assert set(planner.planning_templates) == {
            "FRAUD_PREVENTION", "CYBER_DEFENSE", "COMPLIANCE_ENHANCEMENT"
        }

    def test_template_structure(self):
        planner = Planner()
        template = planner.planning_templates["FRAUD_PREVENTION"]
        assert template["objectives"] == [
            "Reduce fraud losses by 30%",
            "Improve detection accuracy",
            "Minimize false positives",
        ]
        assert template["phases"] == [
            "Phase 1: Enhanced monitoring (30 days)",
            "Phase 2: ML model updates (60 days)",
            "Phase 3: Process automation (90 days)",
        ]
        assert template["metrics"] == ["Fraud rate", "Detection time", "False positive rate"]


class TestPlannerCreateStrategy:
    def test_create_strategy_uses_template(self):
        planner = Planner()
        strategy = planner.create_strategy(
            strategy_type="FRAUD_PREVENTION",
            name="Q4 Fraud Defense Strategy",
            description="Comprehensive fraud prevention plan",
        )
        assert isinstance(strategy, Strategy)
        assert strategy.name == "Q4 Fraud Defense Strategy"
        assert strategy.description == "Comprehensive fraud prevention plan"
        assert strategy.objectives == [
            "Reduce fraud losses by 30%",
            "Improve detection accuracy",
            "Minimize false positives",
        ]
        assert strategy.phases == [
            "Phase 1: Enhanced monitoring (30 days)",
            "Phase 2: ML model updates (60 days)",
            "Phase 3: Process automation (90 days)",
        ]
        assert strategy.success_metrics == [
            "Fraud rate", "Detection time", "False positive rate"
        ]

    def test_create_strategy_unknown_type_defaults_to_cyber_defense(self):
        planner = Planner()
        strategy = planner.create_strategy(
            strategy_type="UNKNOWN",
            name="Fallback",
            description="Uses default template",
        )
        assert strategy.objectives == [
            "Strengthen perimeter security",
            "Improve threat detection",
            "Reduce mean time to respond",
        ]
        assert strategy.phases == [
            "Phase 1: Security audit (30 days)",
            "Phase 2: Control implementation (60 days)",
            "Phase 3: Continuous monitoring (90 days)",
        ]
        assert strategy.success_metrics == ["Incident count", "MTTR", "Coverage"]

    def test_create_strategy_generates_uuid(self, monkeypatch):
        fixed = UUID("11111111-2222-3333-4444-555555555555")
        monkeypatch.setattr("src.metabrain.planner.uuid4", lambda: fixed)
        planner = Planner()
        strategy = planner.create_strategy(
            strategy_type="CYBER_DEFENSE", name="N", description="D"
        )
        assert strategy.strategy_id == "11111111-2222-3333-4444-555555555555"

    def test_create_strategy_stores_in_planner(self):
        planner = Planner()
        strategy = planner.create_strategy(
            strategy_type="COMPLIANCE_ENHANCEMENT",
            name="GDPR Plan",
            description="Compliance",
        )
        assert planner.strategies[strategy.strategy_id] is strategy


class TestPlannerGetStrategy:
    def test_get_strategy_returns_created(self):
        planner = Planner()
        strategy = planner.create_strategy(
            strategy_type="FRAUD_PREVENTION", name="S", description="D"
        )
        assert planner.get_strategy(strategy.strategy_id) is strategy

    def test_get_strategy_missing_returns_none(self):
        planner = Planner()
        assert planner.get_strategy("does-not-exist") is None

    def test_get_all_strategies_empty(self):
        planner = Planner()
        assert planner.get_all_strategies() == []

    def test_get_all_strategies_returns_all(self):
        planner = Planner()
        first = planner.create_strategy(
            strategy_type="FRAUD_PREVENTION", name="A", description="D"
        )
        second = planner.create_strategy(
            strategy_type="CYBER_DEFENSE", name="B", description="D"
        )
        third = planner.create_strategy(
            strategy_type="COMPLIANCE_ENHANCEMENT", name="C", description="D"
        )
        result = planner.get_all_strategies()
        assert len(result) == 3
        assert result == [first, second, third]


class TestPlannerGenerateRoadmap:
    def test_empty_insights_returns_empty_roadmap(self):
        planner = Planner()
        assert planner.generate_roadmap([]) == []

    def test_roadmap_groups_and_orders_by_level(self):
        planner = Planner()
        tactical = make_insight(
            insight_id="t1", title="Phishing", intelligence_level=IntelligenceLevel.TACTICAL
        )
        strategic = make_insight(
            insight_id="s1", title="Layering", intelligence_level=IntelligenceLevel.STRATEGIC
        )
        operational = make_insight(
            insight_id="o1", title="Escalation", intelligence_level=IntelligenceLevel.OPERATIONAL
        )
        roadmap = planner.generate_roadmap([strategic, tactical, operational], timeframe_days=90)
        assert len(roadmap) == 3
        assert roadmap[0] == {
            "phase": "Immediate (0-30 days)",
            "items": ["Tactical: Phishing"],
            "priority": "HIGH",
        }
        assert roadmap[1] == {
            "phase": "Short-term (30-60 days)",
            "items": ["Operational: Escalation"],
            "priority": "MEDIUM",
        }
        assert roadmap[2] == {
            "phase": "Long-term (60-90 days)",
            "items": ["Strategic: Layering"],
            "priority": "LOW",
        }

    def test_roadmap_caps_items_at_five(self):
        planner = Planner()
        tactical = [
            make_insight(
                insight_id=f"t{i}",
                title=f"Alert {i}",
                intelligence_level=IntelligenceLevel.TACTICAL,
            )
            for i in range(6)
        ]
        roadmap = planner.generate_roadmap(tactical)
        assert len(roadmap) == 1
        assert roadmap[0]["phase"] == "Immediate (0-30 days)"
        assert roadmap[0]["items"] == [f"Tactical: Alert {i}" for i in range(5)]

    def test_roadmap_omits_empty_level_groups(self):
        planner = Planner()
        operational = make_insight(
            insight_id="o1", title="Escalation", intelligence_level=IntelligenceLevel.OPERATIONAL
        )
        roadmap = planner.generate_roadmap([operational])
        assert len(roadmap) == 1
        assert roadmap[0]["phase"] == "Short-term (30-60 days)"


class TestRecommendationEngineInit:
    def test_init_templates(self):
        engine = RecommendationEngine()
        assert set(engine.action_templates) == {
            "INVESTIGATE", "BLOCK", "ENHANCE", "ALERT"
        }

    def test_template_structure(self):
        engine = RecommendationEngine()
        assert engine.action_templates["INVESTIGATE"]["estimated_impact"] == "Medium"
        assert engine.action_templates["BLOCK"]["estimated_impact"] == "High"
        assert engine.action_templates["ENHANCE"]["estimated_impact"] == "High"
        assert engine.action_templates["ALERT"]["estimated_impact"] == "Low"
        assert len(engine.action_templates["BLOCK"]["templates"]) == 3


class TestGenerateRecommendations:
    def test_priority_mapping_to_action_type(self):
        engine = RecommendationEngine()
        insights = [
            make_insight(insight_id=f"p{i}", priority=i) for i in range(1, 8)
        ]
        recs = engine.generate_recommendations(insights)
        expected = {
            1: "BLOCK", 2: "BLOCK", 3: "ENHANCE", 4: "ENHANCE",
            5: "INVESTIGATE", 6: "INVESTIGATE", 7: "ALERT",
        }
        assert [r.action_type for r in recs] == [
            expected[i.priority] for i in insights
        ]

    def test_description_uses_template_with_joined_domains(self):
        engine = RecommendationEngine()
        insight = make_insight(
            insight_id="p6",
            title="Suspicious transfers",
            priority=6,
            affected_domains=["payments", "transfers"],
        )
        recs = engine.generate_recommendations([insight])
        rec = recs[0]
        assert rec.action_type == "INVESTIGATE"
        assert rec.title == "Action Required: Suspicious transfers"
        assert rec.description == "Conduct deep investigation on payments, transfers"
        assert rec.target_domain == "payments, transfers"
        assert rec.estimated_impact == "Medium"
        assert rec.confidence == pytest.approx(0.85)

    def test_high_priority_uses_block_template(self):
        engine = RecommendationEngine()
        insight = make_insight(
            insight_id="p1", title="ATO spike", priority=1,
            affected_domains=["account"],
        )
        recs = engine.generate_recommendations([insight])
        assert recs[0].action_type == "BLOCK"
        assert recs[0].description == "Block suspicious activity in account"
        assert recs[0].estimated_impact == "High"

    def test_fallback_description_when_no_template(self):
        engine = RecommendationEngine()
        engine.action_templates = {}
        insight = make_insight(
            insight_id="p1", title="Mule cluster", priority=1,
            affected_domains=["payments"],
        )
        recs = engine.generate_recommendations([insight])
        assert recs[0].description == "Address insight: Mule cluster"
        assert recs[0].estimated_impact == "Medium"

    def test_generate_uses_uuid(self, monkeypatch):
        fixed = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        monkeypatch.setattr("src.metabrain.recommendation_engine.uuid4", lambda: fixed)
        engine = RecommendationEngine()
        recs = engine.generate_recommendations(
            [make_insight(insight_id="p3", priority=3)]
        )
        assert recs[0].recommendation_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_empty_insights_returns_empty(self):
        engine = RecommendationEngine()
        assert engine.generate_recommendations([]) == []
        assert engine.recommendations == []

    def test_appends_to_stored_recommendations(self):
        engine = RecommendationEngine()
        engine.generate_recommendations([make_insight(insight_id="a", priority=2)])
        engine.generate_recommendations([make_insight(insight_id="b", priority=7)])
        assert len(engine.recommendations) == 2


class TestGetRecommendationsByPriority:
    def test_slices_to_max_results(self):
        engine = RecommendationEngine()
        engine.generate_recommendations(
            [make_insight(insight_id=f"p{i}", priority=i) for i in range(1, 5)]
        )
        result = engine.get_recommendations_by_priority(min_priority=0, max_results=2)
        assert len(result) == 2
        assert result[0] is engine.recommendations[0]
        assert result[1] is engine.recommendations[1]

    def test_max_results_beyond_length_returns_all(self):
        engine = RecommendationEngine()
        engine.generate_recommendations([make_insight(insight_id="a", priority=1)])
        assert len(engine.get_recommendations_by_priority(max_results=100)) == 1

    def test_empty_recommendations(self):
        engine = RecommendationEngine()
        assert engine.get_recommendations_by_priority() == []


class TestGetRecommendationsByDomain:
    def test_filters_by_domain(self):
        engine = RecommendationEngine()
        engine.generate_recommendations([
            make_insight(
                insight_id="a", priority=1, affected_domains=["payments"]
            ),
            make_insight(
                insight_id="b", priority=2, affected_domains=["identity", "kms"]
            ),
            make_insight(
                insight_id="c", priority=3, affected_domains=["transfers"]
            ),
        ])
        result = engine.get_recommendations_by_domain("payments")
        assert len(result) == 1
        assert result[0].target_domain == "payments"

    def test_case_insensitive_match(self):
        engine = RecommendationEngine()
        engine.generate_recommendations([
            make_insight(
                insight_id="a", priority=1, affected_domains=["Identity"]
            )
        ])
        result = engine.get_recommendations_by_domain("IDENTITY")
        assert len(result) == 1

    def test_partial_domain_match(self):
        engine = RecommendationEngine()
        engine.generate_recommendations([
            make_insight(
                insight_id="a", priority=1, affected_domains=["payments", "transfers"]
            )
        ])
        assert len(engine.get_recommendations_by_domain("transfer")) == 1

    def test_no_match_returns_empty(self):
        engine = RecommendationEngine()
        engine.generate_recommendations([
            make_insight(insight_id="a", priority=1, affected_domains=["payments"])
        ])
        assert engine.get_recommendations_by_domain("crypto") == []


class TestGetRecommendationStats:
    def test_stats_counts_and_average(self):
        engine = RecommendationEngine()
        engine.generate_recommendations([
            make_insight(insight_id="a", priority=1, confidence=0.9),
            make_insight(insight_id="b", priority=3, confidence=0.8),
            make_insight(insight_id="c", priority=4, confidence=0.7),
            make_insight(insight_id="d", priority=7, confidence=0.6),
        ])
        stats = engine.get_recommendation_stats()
        assert stats["total_recommendations"] == 4
        assert stats["action_distribution"] == {
            "BLOCK": 1, "ENHANCE": 2, "ALERT": 1
        }
        assert stats["avg_confidence"] == pytest.approx(0.75)

    def test_stats_empty(self):
        engine = RecommendationEngine()
        stats = engine.get_recommendation_stats()
        assert stats == {
            "total_recommendations": 0,
            "action_distribution": {},
            "avg_confidence": 0,
        }
