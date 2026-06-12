"""
Tests for Autonomous Fraud Investigation & Decision Intelligence Platform.
"""

import pytest
from datetime import datetime, timezone

from src.autonomous_investigation import (
    # Models
    InvestigationStatus,
    EvidenceType,
    RiskLevel,
    DecisionType,
    CasePriority,
    SeverityLevel,
    InvestigationCase,
    EvidenceArtifact,
    RiskAssessment,
    DecisionRecommendation,
    # Store
    get_investigation_store,
    reset_store,
    # Engines
    get_investigation_engine,
    get_evidence_collector,
    get_decision_engine,
    get_case_prioritization_engine,
    get_recommendation_engine,
    get_explainability_engine,
    # Service
    get_investigation_service,
)


class TestModels:
    """Test data models."""

    def test_investigation_case_creation(self):
        """Test investigation case model."""
        case = InvestigationCase(
            case_id="case-1",
            title="Test Investigation",
            description="Testing case creation",
            status=InvestigationStatus.CREATED,
            priority=CasePriority.P2_MEDIUM,
            severity=SeverityLevel.MODERATE,
            entity_ids=["entity-1", "entity-2"],
        )

        assert case.case_id == "case-1"
        assert case.title == "Test Investigation"
        assert case.status == InvestigationStatus.CREATED
        assert len(case.entity_ids) == 2

    def test_evidence_artifact(self):
        """Test evidence artifact model."""
        artifact = EvidenceArtifact(
            evidence_id="evidence-1",
            evidence_type=EvidenceType.TRANSACTION,
            source_system="transaction_db",
            source_id="txn-123",
            content={"amount": 5000, "currency": "USD"},
            relevance_score=0.9,
        )

        assert artifact.evidence_id == "evidence-1"
        assert artifact.evidence_type == EvidenceType.TRANSACTION
        assert artifact.relevance_score == 0.9


class TestInvestigationStore:
    """Test investigation store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_store()

    def test_case_storage(self):
        """Test storing and retrieving cases."""
        store = get_investigation_store()

        case = InvestigationCase(
            case_id="case-1",
            title="Test",
            description="Test",
            status=InvestigationStatus.CREATED,
            priority=CasePriority.P2_MEDIUM,
            severity=SeverityLevel.MODERATE,
        )

        store.store_case(case)
        retrieved = store.get_case("case-1")

        assert retrieved is not None
        assert retrieved.case_id == "case-1"

    def test_case_by_status(self):
        """Test getting cases by status."""
        store = get_investigation_store()

        for i in range(3):
            case = InvestigationCase(
                case_id=f"case-{i}",
                title=f"Case {i}",
                description="Test",
                status=InvestigationStatus.CREATED,
                priority=CasePriority.P2_MEDIUM,
                severity=SeverityLevel.MODERATE,
            )
            store.store_case(case)

        cases = store.get_cases_by_status(InvestigationStatus.CREATED.value)
        assert len(cases) == 3

    def test_update_case_status(self):
        """Test updating case status."""
        store = get_investigation_store()

        case = InvestigationCase(
            case_id="case-1",
            title="Test",
            description="Test",
            status=InvestigationStatus.CREATED,
            priority=CasePriority.P2_MEDIUM,
            severity=SeverityLevel.MODERATE,
        )
        store.store_case(case)

        success = store.update_case_status("case-1", InvestigationStatus.IN_PROGRESS)
        assert success is True

        retrieved = store.get_case("case-1")
        assert retrieved.status == InvestigationStatus.IN_PROGRESS


class TestInvestigationEngine:
    """Test investigation engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_store()

    def test_create_investigation(self):
        """Test creating an investigation."""
        engine = get_investigation_engine()

        case = engine.create_investigation(
            title="Test Investigation",
            description="Testing investigation creation",
            entity_ids=["entity-1", "entity-2"],
            priority=CasePriority.P1_HIGH,
        )

        assert case.case_id is not None
        assert case.title == "Test Investigation"
        assert case.priority == CasePriority.P1_HIGH

    def test_get_investigation_summary(self):
        """Test getting investigation summary."""
        engine = get_investigation_engine()

        case = engine.create_investigation(
            title="Test",
            description="Test",
        )

        summary = engine.get_investigation_summary(case.case_id)

        assert "case_id" in summary
        assert summary["title"] == "Test"


class TestEvidenceCollector:
    """Test evidence collector."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_collect_evidence(self):
        """Test evidence collection."""
        import asyncio

        collector = get_evidence_collector()

        async def run_test():
            evidence = await collector.collect_evidence(
                entity_ids=["entity-1", "entity-2"],
                alert_ids=["alert-1"],
            )
            return evidence

        evidence = asyncio.run(run_test())

        assert isinstance(evidence, list)


class TestDecisionIntelligence:
    """Test decision intelligence engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_generate_decision(self):
        """Test decision generation."""
        import asyncio

        engine = get_decision_engine()
        store = get_investigation_store()

        case = InvestigationCase(
            case_id="case-1",
            title="Test",
            description="Test",
            status=InvestigationStatus.CREATED,
            priority=CasePriority.P2_MEDIUM,
            severity=SeverityLevel.MODERATE,
            risk_score=0.7,
        )
        store.store_case(case)

        async def run_test():
            decision = await engine.generate_decision(
                case=case,
                evidence=[],
                assessment=None,
            )
            return decision

        decision = asyncio.run(run_test())

        assert decision.case_id == "case-1"
        assert decision.confidence > 0


class TestCasePrioritization:
    """Test case prioritization engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_calculate_priority_score(self):
        """Test priority score calculation."""
        engine = get_case_prioritization_engine()

        case = InvestigationCase(
            case_id="case-1",
            title="Test",
            description="Test",
            status=InvestigationStatus.CREATED,
            priority=CasePriority.P0_CRITICAL,
            severity=SeverityLevel.CRITICAL,
            risk_score=0.9,
        )

        score = engine.calculate_priority_score(case)

        assert score > 0.5
        assert score <= 1.0

    def test_determine_priority(self):
        """Test priority determination."""
        engine = get_case_prioritization_engine()

        case = InvestigationCase(
            case_id="case-1",
            title="Test",
            description="Test",
            status=InvestigationStatus.CREATED,
            priority=CasePriority.P0_CRITICAL,
            severity=SeverityLevel.CRITICAL,
            risk_score=0.95,
        )

        priority = engine.determine_priority(case)

        assert priority in CasePriority

    def test_prioritize_queue(self):
        """Test queue prioritization."""
        engine = get_case_prioritization_engine()

        cases = []
        for i in range(5):
            case = InvestigationCase(
                case_id=f"case-{i}",
                title=f"Case {i}",
                description="Test",
                status=InvestigationStatus.CREATED,
                priority=CasePriority.P2_MEDIUM,
                severity=SeverityLevel.MODERATE,
                risk_score=i / 10,
            )
            cases.append(case)

        prioritized = engine.prioritize_queue(cases)

        assert len(prioritized) == 5
        # First case should have highest risk score
        assert prioritized[0].risk_score >= prioritized[-1].risk_score


class TestRecommendationEngine:
    """Test recommendation engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_get_next_action(self):
        """Test getting next action."""
        import asyncio

        engine = get_recommendation_engine()
        store = get_investigation_store()

        case = InvestigationCase(
            case_id="case-1",
            title="Test",
            description="Test",
            status=InvestigationStatus.CREATED,
            priority=CasePriority.P2_MEDIUM,
            severity=SeverityLevel.MODERATE,
        )
        store.store_case(case)

        async def run_test():
            action = await engine.get_next_action_suggestion(case, [])
            return action

        action = asyncio.run(run_test())

        assert isinstance(action, str)
        assert len(action) > 0


class TestExplainability:
    """Test explainability engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_explain_decision(self):
        """Test decision explanation."""
        import asyncio

        engine = get_explainability_engine()

        case = InvestigationCase(
            case_id="case-1",
            title="Test",
            description="Test",
            status=InvestigationStatus.CREATED,
            priority=CasePriority.P2_MEDIUM,
            severity=SeverityLevel.MODERATE,
            risk_score=0.7,
        )

        decision = DecisionRecommendation(
            recommendation_id="rec-1",
            case_id="case-1",
            decision_type=DecisionType.FLAG,
            confidence=0.8,
            supporting_evidence=["e1", "e2"],
            risk_explanation="Test explanation",
            recommended_actions=["Action 1"],
            decision_date=datetime.now(timezone.utc),
            model_id="test",
        )

        async def run_test():
            explanation = await engine.explain_decision(decision, case, [])
            return explanation

        explanation = asyncio.run(run_test())

        assert "explanation_id" in explanation
        assert explanation["confidence"] == 0.8


class TestInvestigationService:
    """Test main investigation service."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_create_investigation(self):
        """Test creating investigation via service."""
        import asyncio

        service = get_investigation_service()

        async def run_test():
            result = await service.create_investigation(
                title="Test Investigation",
                description="Testing service",
                entity_ids=["entity-1"],
                priority="p1_high",
            )
            return result

        result = asyncio.run(run_test())

        assert "case_id" in result
        assert result["title"] == "Test Investigation"

    def test_list_investigations(self):
        """Test listing investigations."""
        import asyncio

        service = get_investigation_service()

        async def run_test():
            # Create a case first
            await service.create_investigation(
                title="Test",
                description="Test",
            )
            # List investigations
            result = await service.list_investigations()
            return result

        result = asyncio.run(run_test())

        assert isinstance(result, list)
        assert len(result) >= 1

    def test_get_dashboard(self):
        """Test getting dashboard."""
        import asyncio

        service = get_investigation_service()

        async def run_test():
            dashboard = await service.get_dashboard()
            return dashboard

        dashboard = asyncio.run(run_test())

        assert "total_cases" in dashboard
        assert "open_cases" in dashboard


class TestRiskAssessment:
    """Test risk assessment functionality."""

    def test_risk_assessment_model(self):
        """Test risk assessment model."""
        assessment = RiskAssessment(
            assessment_id="assess-1",
            case_id="case-1",
            risk_level=RiskLevel.HIGH,
            risk_score=0.85,
            risk_factors=["High transaction velocity", "New device"],
            risk_categories={"velocity": 0.9, "device": 0.7},
            mitigation_factors=["Verified customer"],
            residual_risk=0.3,
            assessment_date=datetime.now(timezone.utc),
        )

        assert assessment.risk_score == 0.85
        assert assessment.risk_level == RiskLevel.HIGH
        assert len(assessment.risk_factors) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])