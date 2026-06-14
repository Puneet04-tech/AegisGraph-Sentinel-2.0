"""
Tests for Multi-Agent Fraud Security Operations Center (SOC).

Comprehensive tests for:
    - Investigation Agent
    - Threat Intelligence Agent
    - Forensics Agent
    - Fraud Ring Agent
    - Reporting Agent
    - Agent Orchestrator
    - API Endpoints
"""

import pytest
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from src.multi_agent_soc import (
    AgentType,
    AgentStatus,
    TaskPriority,
    TaskStatus,
    InvestigationStatus,
    AgentTask,
    AgentState,
    InvestigationResult,
    ThreatIntelligenceReport,
    ForensicAnalysis,
    FraudRingAnalysis,
    SOCReport,
    AgentMessage,
    OrchestrationPlan,
    SOCStore,
    get_soc_store,
    InvestigationAgent,
    get_investigation_agent,
    ThreatIntelligenceAgent,
    get_threat_intelligence_agent,
    ForensicsAgent,
    get_forensics_agent,
    FraudRingAgent,
    get_fraud_ring_agent,
    ReportingAgent,
    get_reporting_agent,
    AgentOrchestrator,
    get_orchestrator,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def store():
    """Create a fresh SOC store for testing."""
    return SOCStore(max_size=100)


@pytest.fixture
def investigation_agent(store):
    """Create an investigation agent with fresh store."""
    return InvestigationAgent(store=store)


@pytest.fixture
def threat_agent(store):
    """Create a threat intelligence agent with fresh store."""
    return ThreatIntelligenceAgent(store=store)


@pytest.fixture
def forensics_agent(store):
    """Create a forensics agent with fresh store."""
    return ForensicsAgent(store=store)


@pytest.fixture
def fraud_ring_agent(store):
    """Create a fraud ring agent with fresh store."""
    return FraudRingAgent(store=store)


@pytest.fixture
def reporting_agent(store):
    """Create a reporting agent with fresh store."""
    return ReportingAgent(store=store)


@pytest.fixture
def orchestrator(store):
    """Create an agent orchestrator with fresh store."""
    return AgentOrchestrator(store=store)


# =============================================================================
# Model Tests
# =============================================================================

class TestSOCModels:
    """Tests for SOC data models."""
    
    def test_agent_task_creation(self):
        """Test creating an agent task."""
        task = AgentTask(
            agent_type=AgentType.INVESTIGATION,
            title="Test Task",
            description="Test description",
            priority=TaskPriority.HIGH,
        )
        
        assert task.task_id is not None
        assert task.agent_type == AgentType.INVESTIGATION
        assert task.priority == TaskPriority.HIGH
        assert task.status == TaskStatus.PENDING
    
    def test_agent_task_to_dict(self):
        """Test converting task to dictionary."""
        task = AgentTask(
            agent_type=AgentType.FORENSICS,
            title="Forensics Task",
            description="Test task",
        )
        
        data = task.to_dict()
        
        assert "task_id" in data
        assert data["agent_type"] == "FORENSICS"
        assert data["priority"] == "MEDIUM"
    
    def test_investigation_result_creation(self):
        """Test creating investigation result."""
        result = InvestigationResult(
            entity_id="entity_1",
            status=InvestigationStatus.IN_PROGRESS,
            risk_score=0.75,
            confidence=0.8,
        )
        
        assert result.investigation_id is not None
        assert result.entity_id == "entity_1"
        assert result.risk_score == 0.75
    
    def test_threat_intelligence_report_creation(self):
        """Test creating threat intelligence report."""
        report = ThreatIntelligenceReport(
            threat_type="credential_stuffing",
            severity="HIGH",
            confidence=0.85,
            description="Test threat",
        )
        
        assert report.report_id is not None
        assert report.threat_type == "credential_stuffing"
        assert report.severity == "HIGH"
    
    def test_forensic_analysis_creation(self):
        """Test creating forensic analysis."""
        analysis = ForensicAnalysis(
            target_entity_id="entity_1",
            analysis_type="transaction",
            conclusion="SUSPICIOUS",
            confidence=0.85,
        )
        
        assert analysis.analysis_id is not None
        assert analysis.target_entity_id == "entity_1"
    
    def test_fraud_ring_analysis_creation(self):
        """Test creating fraud ring analysis."""
        ring = FraudRingAnalysis(
            ring_name="Test Ring",
            ring_score=0.85,
            ring_type="money_laundering",
            financial_impact=100000.0,
            confidence=0.85,
        )
        
        assert ring.ring_id is not None
        assert ring.ring_score == 0.85
    
    def test_soc_report_creation(self):
        """Test creating SOC report."""
        now = datetime.now(timezone.utc)
        report = SOCReport(
            report_type="daily",
            period_start=now,
            period_end=now,
        )
        
        assert report.report_id is not None
        assert report.report_type == "daily"
    
    def test_orchestration_plan_creation(self):
        """Test creating orchestration plan."""
        plan = OrchestrationPlan(
            title="Test Workflow",
            description="Test workflow description",
            estimated_duration_seconds=300,
        )
        
        assert plan.plan_id is not None
        assert plan.title == "Test Workflow"
        assert len(plan.tasks) == 0


# =============================================================================
# Store Tests
# =============================================================================

class TestSOCStore:
    """Tests for SOCStore."""
    
    def test_store_and_retrieve_task(self, store):
        """Test storing and retrieving tasks."""
        task = AgentTask(
            agent_type=AgentType.INVESTIGATION,
            title="Test Task",
            description="Test description",
        )
        
        stored = store.store_task(task)
        retrieved = store.get_task(task.task_id)
        
        assert retrieved is not None
        assert retrieved.task_id == task.task_id
    
    def test_get_pending_tasks(self, store):
        """Test getting pending tasks."""
        tasks = [
            AgentTask(agent_type=AgentType.INVESTIGATION, title=f"Task {i}", description="Test", priority=TaskPriority.HIGH)
            for i in range(3)
        ]
        
        for t in tasks:
            store.store_task(t)
        
        pending = store.get_pending_tasks()
        
        assert len(pending) >= 3
    
    def test_store_investigation(self, store):
        """Test storing investigation results."""
        result = InvestigationResult(
            entity_id="entity_1",
            status=InvestigationStatus.CLOSED,
            risk_score=0.5,
            confidence=0.8,
        )
        
        stored = store.store_investigation(result)
        retrieved = store.get_investigation(result.investigation_id)
        
        assert retrieved is not None
        assert retrieved.entity_id == "entity_1"
    
    def test_store_threat_report(self, store):
        """Test storing threat reports."""
        report = ThreatIntelligenceReport(
            threat_type="phishing",
            severity="MEDIUM",
            confidence=0.8,
            description="Test report",
        )
        
        stored = store.store_threat_report(report)
        retrieved = store.get_threat_report(report.report_id)
        
        assert retrieved is not None
        assert retrieved.threat_type == "phishing"
    
    def test_store_fraud_ring(self, store):
        """Test storing fraud ring analysis."""
        ring = FraudRingAnalysis(
            ring_name="Test Ring",
            ring_score=0.8,
            ring_type="money_laundering",
            financial_impact=50000.0,
            confidence=0.8,
        )
        
        stored = store.store_fraud_ring(ring)
        retrieved = store.get_fraud_ring(ring.ring_id)
        
        assert retrieved is not None
        assert retrieved.ring_name == "Test Ring"
    
    def test_store_report(self, store):
        """Test storing SOC reports."""
        now = datetime.now(timezone.utc)
        report = SOCReport(
            report_type="weekly",
            period_start=now,
            period_end=now,
        )
        
        stored = store.store_report(report)
        retrieved = store.get_report(report.report_id)
        
        assert retrieved is not None
        assert retrieved.report_type == "weekly"
    
    def test_store_plan(self, store):
        """Test storing orchestration plans."""
        plan = OrchestrationPlan(
            title="Test Plan",
            description="Test plan description",
            estimated_duration_seconds=600,
        )
        
        stored = store.store_plan(plan)
        retrieved = store.get_plan(plan.plan_id)
        
        assert retrieved is not None
        assert retrieved.title == "Test Plan"
    
    def test_get_stats(self, store):
        """Test getting store statistics."""
        stats = store.get_stats()
        
        assert "total_agents" in stats
        assert "total_tasks" in stats
        assert stats["total_agents"] >= 5  # Default agents


# =============================================================================
# Investigation Agent Tests
# =============================================================================

class TestInvestigationAgent:
    """Tests for InvestigationAgent."""
    
    def test_analyze_entity(self, investigation_agent):
        """Test entity analysis."""
        result = investigation_agent.analyze_entity("entity_1")
        
        assert result.entity_id == "entity_1"
        assert result.investigation_id is not None
        assert 0 <= result.risk_score <= 1.0
    
    def test_triage_alerts(self, investigation_agent):
        """Test alert triage."""
        alert_ids = ["alert_1", "alert_2", "alert_3"]
        tasks = investigation_agent.triage_alerts(alert_ids, TaskPriority.HIGH)
        
        assert len(tasks) == 3
        assert all(t.priority == TaskPriority.HIGH for t in tasks)
    
    def test_create_investigation(self, investigation_agent):
        """Test creating investigation task."""
        task = investigation_agent.create_investigation(
            entity_id="entity_1",
            case_id="case_1",
            priority=TaskPriority.CRITICAL,
        )
        
        assert task.agent_type == AgentType.INVESTIGATION
        assert task.priority == TaskPriority.CRITICAL
        assert "entity_1" in task.context["entity_id"]
    
    def test_get_investigation_summary(self, investigation_agent):
        """Test getting investigation summary."""
        investigation_agent.analyze_entity("entity_1")
        investigation_agent.analyze_entity("entity_1")
        
        summary = investigation_agent.get_investigation_summary("entity_1")
        
        assert summary["total_investigations"] >= 1


# =============================================================================
# Threat Intelligence Agent Tests
# =============================================================================

class TestThreatIntelligenceAgent:
    """Tests for ThreatIntelligenceAgent."""
    
    def test_analyze_threat(self, threat_agent):
        """Test threat analysis."""
        indicators = [{"type": "ip", "value": "1.2.3.4"}]
        report = threat_agent.analyze_threat(
            threat_type="credential_stuffing",
            indicators=indicators,
        )
        
        assert report.report_id is not None
        assert report.threat_type == "credential_stuffing"
        assert report.confidence > 0
    
    def test_enrich_ioc(self, threat_agent):
        """Test IOC enrichment."""
        ioc = {"type": "ip_address", "value": "1.2.3.4"}
        enriched = threat_agent.enrich_ioc(ioc)
        
        assert "confidence_score" in enriched
        assert enriched["type"] == "ip_address"
    
    def test_track_threat_actor(self, threat_agent):
        """Test threat actor tracking."""
        activity = {"campaigns": 5, "ttps": ["T1078"]}
        tracked = threat_agent.track_threat_actor("test_actor", activity)
        
        assert tracked["actor_name"] == "test_actor"
        assert "last_activity" in tracked
    
    def test_create_threat_hunt_task(self, threat_agent):
        """Test creating threat hunt task."""
        task = threat_agent.create_threat_hunt_task(
            hypothesis="Credential stuffing attack in progress",
            indicators=["1.2.3.4", "5.6.7.8"],
            priority=TaskPriority.CRITICAL,
        )
        
        assert task.agent_type == AgentType.THREAT_INTELLIGENCE
        assert task.priority == TaskPriority.CRITICAL
    
    def test_get_active_threats(self, threat_agent):
        """Test getting active threats."""
        threat_agent.analyze_threat("test_threat", [])
        threats = threat_agent.get_active_threats(hours=1)
        
        assert len(threats) >= 1


# =============================================================================
# Forensics Agent Tests
# =============================================================================

class TestForensicsAgent:
    """Tests for ForensicsAgent."""
    
    def test_perform_forensics(self, forensics_agent):
        """Test performing forensics."""
        analysis = forensics_agent.perform_forensics(
            target_entity_id="entity_1",
            analysis_type="transaction",
        )
        
        assert analysis.analysis_id is not None
        assert analysis.target_entity_id == "entity_1"
        assert analysis.analysis_type == "transaction"
    
    def test_collect_evidence(self, forensics_agent):
        """Test evidence collection."""
        evidence_types = ["transaction_log", "access_log"]
        collected = forensics_agent.collect_evidence(
            entity_id="entity_1",
            evidence_types=evidence_types,
        )
        
        assert len(collected) == 2
        assert all(e["entity_id"] == "entity_1" for e in collected)
    
    def test_verify_evidence_integrity(self, forensics_agent):
        """Test evidence integrity verification."""
        hash1 = "abc123"
        hash2 = "abc123"
        result = forensics_agent.verify_evidence_integrity(hash1, hash2)
        
        assert result is True
    
    def test_create_forensics_task(self, forensics_agent):
        """Test creating forensics task."""
        task = forensics_agent.create_forensics_task(
            entity_id="entity_1",
            analysis_type="comprehensive",
            priority=TaskPriority.HIGH,
        )
        
        assert task.agent_type == AgentType.FORENSICS
        assert task.priority == TaskPriority.HIGH
    
    def test_get_entity_forensics(self, forensics_agent):
        """Test getting entity forensics."""
        forensics_agent.perform_forensics("entity_1", "transaction")
        forensics_list = forensics_agent.get_entity_forensics("entity_1")
        
        assert len(forensics_list) >= 1


# =============================================================================
# Fraud Ring Agent Tests
# =============================================================================

class TestFraudRingAgent:
    """Tests for FraudRingAgent."""
    
    def test_detect_ring(self, fraud_ring_agent):
        """Test fraud ring detection."""
        analysis = fraud_ring_agent.detect_ring(
            seed_entities=["entity_1", "entity_2"],
            ring_type="money_laundering",
        )
        
        assert analysis.ring_id is not None
        assert len(analysis.member_entities) > 0
        assert analysis.ring_score > 0
    
    def test_analyze_ring_expansion(self, fraud_ring_agent):
        """Test ring expansion analysis."""
        analysis = fraud_ring_agent.detect_ring(["entity_1"], "test")
        
        expansion = fraud_ring_agent.analyze_ring_expansion(
            ring_id=analysis.ring_id,
            new_entity="new_entity",
        )
        
        assert "can_add" in expansion
        assert "connection_strength" in expansion
    
    def test_create_ring_detection_task(self, fraud_ring_agent):
        """Test creating ring detection task."""
        task = fraud_ring_agent.create_ring_detection_task(
            seed_entities=["entity_1", "entity_2"],
            ring_type="payment_fraud",
            priority=TaskPriority.CRITICAL,
        )
        
        assert task.agent_type == AgentType.FRAUD_RING
        assert task.priority == TaskPriority.CRITICAL
    
    def test_get_ring_details(self, fraud_ring_agent):
        """Test getting ring details."""
        analysis = fraud_ring_agent.detect_ring(["entity_1"], "test")
        details = fraud_ring_agent.get_ring_details(analysis.ring_id)
        
        assert details is not None
        assert details.ring_id == analysis.ring_id
    
    def test_get_high_risk_rings(self, fraud_ring_agent):
        """Test getting high-risk rings."""
        fraud_ring_agent.detect_ring(["entity_1"], "high_risk")
        rings = fraud_ring_agent.get_high_risk_rings(threshold=0.5)
        
        assert isinstance(rings, list)


# =============================================================================
# Reporting Agent Tests
# =============================================================================

class TestReportingAgent:
    """Tests for ReportingAgent."""
    
    def test_generate_summary_report(self, reporting_agent):
        """Test generating summary report."""
        now = datetime.now(timezone.utc)
        report = reporting_agent.generate_summary_report(
            period_start=now,
            period_end=now,
            report_type="daily",
        )
        
        assert report.report_id is not None
        assert report.report_type == "daily"
        assert len(report.metrics) > 0
    
    def test_generate_executive_dashboard(self, reporting_agent):
        """Test generating executive dashboard."""
        dashboard = reporting_agent.generate_executive_dashboard()
        
        assert "overview" in dashboard
        assert "trends" in dashboard
        assert "performance" in dashboard
    
    def test_generate_compliance_report(self, reporting_agent):
        """Test generating compliance report."""
        report = reporting_agent.generate_compliance_report(framework="SOC2")
        
        assert report["framework"] == "SOC2"
        assert "controls" in report
    
    def test_generate_threat_trend_report(self, reporting_agent):
        """Test generating threat trend report."""
        trends = reporting_agent.generate_threat_trend_report(days=30)
        
        assert trends["period_days"] == 30
        assert "top_threats" in trends
    
    def test_create_reporting_task(self, reporting_agent):
        """Test creating reporting task."""
        task = reporting_agent.create_reporting_task(
            report_type="weekly",
            priority=TaskPriority.MEDIUM,
        )
        
        assert task.agent_type == AgentType.REPORTING
    
    def test_get_recent_reports(self, reporting_agent):
        """Test getting recent reports."""
        reporting_agent.generate_summary_report(
            datetime.now(timezone.utc),
            datetime.now(timezone.utc),
        )
        reports = reporting_agent.get_recent_reports(hours=1)
        
        assert len(reports) >= 1


# =============================================================================
# Orchestrator Tests
# =============================================================================

class TestAgentOrchestrator:
    """Tests for AgentOrchestrator."""
    
    def test_orchestrate_investigation(self, orchestrator):
        """Test orchestrating multi-agent investigation."""
        results = orchestrator.orchestrate_investigation(
            entity_id="entity_1",
            priority=TaskPriority.HIGH,
        )
        
        assert "investigation" in results
        assert "report" in results
    
    def test_create_workflow(self, orchestrator):
        """Test creating workflow."""
        tasks = [
            {"agent_type": "INVESTIGATION", "title": "Task 1", "priority": "HIGH"},
            {"agent_type": "THREAT_INTELLIGENCE", "title": "Task 2", "priority": "MEDIUM"},
        ]
        
        plan = orchestrator.create_workflow("Test Workflow", tasks)
        
        assert plan.plan_id is not None
        assert len(plan.tasks) == 2
    
    def test_execute_plan(self, orchestrator):
        """Test executing orchestration plan."""
        tasks = [
            {"agent_type": "INVESTIGATION", "title": "Task 1"},
        ]
        
        plan = orchestrator.create_workflow("Test Plan", tasks)
        results = orchestrator.execute_plan(plan.plan_id)
        
        assert "completed" in results
    
    def test_coordinate_agents(self, orchestrator):
        """Test agent coordination."""
        messages = orchestrator.coordinate_agents(
            source_agent=AgentType.INVESTIGATION,
            target_agents=[AgentType.FORENSICS, AgentType.REPORTING],
            message={"type": "task_delegation", "content": {"task_id": "123"}},
        )
        
        assert len(messages) == 2
        assert all(m.from_agent == "INVESTIGATION_agent" for m in messages)
    
    def test_get_orchestration_status(self, orchestrator):
        """Test getting orchestration status."""
        status = orchestrator.get_orchestration_status()
        
        assert "total_agents" in status
        assert "active_tasks" in status
        assert len(status["agent_types"]) == 5


# =============================================================================
# Integration Tests
# =============================================================================

class TestSOCIntegration:
    """Integration tests for SOC workflow."""
    
    def test_full_investigation_workflow(self, investigation_agent, threat_agent, forensics_agent, fraud_ring_agent, reporting_agent, orchestrator):
        """Test full investigation workflow."""
        # 1. Conduct investigation
        inv_result = investigation_agent.analyze_entity("entity_1")
        
        # 2. If high risk, analyze threat
        if inv_result.risk_score >= 0.7:
            threat_report = threat_agent.analyze_threat("high_risk", [])
        
        # 3. Perform forensics
        forensics = forensics_agent.perform_forensics("entity_1", "comprehensive")
        
        # 4. Detect fraud ring
        ring = fraud_ring_agent.detect_ring(["entity_1"], "connected")
        
        # 5. Generate report
        now = datetime.now(timezone.utc)
        report = reporting_agent.generate_summary_report(now, now)
        
        # Verify workflow
        assert inv_result.risk_score > 0
        assert forensics.analysis_id is not None
        assert ring.ring_id is not None
        assert report.report_id is not None
    
    def test_orchestrator_full_workflow(self, orchestrator):
        """Test orchestrator full workflow."""
        # Create workflow
        tasks = [
            {"agent_type": "INVESTIGATION", "title": "Investigate", "priority": "HIGH"},
            {"agent_type": "THREAT_INTELLIGENCE", "title": "Threat Analysis", "priority": "HIGH"},
        ]
        
        plan = orchestrator.create_workflow("Full Investigation", tasks)
        
        # Execute plan
        results = orchestrator.execute_plan(plan.plan_id)
        
        assert plan.plan_id is not None
        assert len(results["completed"]) >= 0


# =============================================================================
# Performance Tests
# =============================================================================

class TestSOCPerformance:
    """Performance tests for SOC."""
    
    def test_investigation_performance(self, investigation_agent):
        """Test investigation performance."""
        start_time = time.time()
        
        for i in range(50):
            investigation_agent.analyze_entity(f"entity_{i}")
        
        duration = (time.time() - start_time) * 1000
        
        assert duration < 5000  # 50 investigations in under 5 seconds
    
    def test_threat_analysis_performance(self, threat_agent):
        """Test threat analysis performance."""
        start_time = time.time()
        
        for i in range(50):
            threat_agent.analyze_threat(f"threat_{i}", [])
        
        duration = (time.time() - start_time) * 1000
        
        assert duration < 5000


# =============================================================================
# Security and RBAC Tests
# =============================================================================

class TestSOCSecurity:
    """Security tests for SOC."""
    
    def test_task_priority_validation(self, investigation_agent):
        """Test task priority validation."""
        priorities = [TaskPriority.CRITICAL, TaskPriority.HIGH, TaskPriority.MEDIUM, TaskPriority.LOW]
        
        for priority in priorities:
            task = investigation_agent.create_investigation(
                entity_id="entity_1",
                priority=priority,
            )
            assert task.priority == priority
    
    def test_investigation_status_transitions(self, investigation_agent):
        """Test investigation status transitions."""
        result = investigation_agent.analyze_entity("entity_1")
        
        # Valid statuses should be assignable
        for status in InvestigationStatus:
            result.status = status
    
    def test_agent_type_coverage(self, store):
        """Test all agent types are registered."""
        expected_types = [
            AgentType.INVESTIGATION,
            AgentType.THREAT_INTELLIGENCE,
            AgentType.FORENSICS,
            AgentType.FRAUD_RING,
            AgentType.REPORTING,
        ]
        
        stats = store.get_stats()
        assert stats["total_agents"] >= len(expected_types)