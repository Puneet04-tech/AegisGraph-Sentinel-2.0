"""
Tests for Executive Governance Platform.

Comprehensive tests for:
    - Executive Dashboard
    - Board Reporting
    - Compliance Analytics
    - Risk Governance
    - Audit Intelligence
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from src.executive_governance import (
    RiskLevel,
    ComplianceStatus,
    AuditFindingSeverity,
    ReportType,
    GovernanceMetric,
    RiskScorecard,
    ComplianceFramework,
    AuditFinding,
    ExecutiveDashboard,
    GovernanceReport,
    GovernanceStore,
    get_governance_store,
    ExecutiveDashboardModule,
    get_executive_dashboard_module,
    BoardReportingModule,
    get_board_reporting_module,
    ComplianceAnalyticsModule,
    get_compliance_analytics_module,
    RiskGovernanceModule,
    get_risk_governance_module,
    AuditIntelligenceModule,
    get_audit_intelligence_module,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def store():
    """Create a fresh governance store for testing."""
    return GovernanceStore(max_size=100)


@pytest.fixture
def dashboard_module(store):
    """Create an executive dashboard module."""
    return ExecutiveDashboardModule(store=store)


@pytest.fixture
def board_reporting(store):
    """Create a board reporting module."""
    return BoardReportingModule(store=store)


@pytest.fixture
def compliance_analytics(store):
    """Create a compliance analytics module."""
    return ComplianceAnalyticsModule(store=store)


@pytest.fixture
def risk_governance(store):
    """Create a risk governance module."""
    return RiskGovernanceModule(store=store)


@pytest.fixture
def audit_intelligence(store):
    """Create an audit intelligence module."""
    return AuditIntelligenceModule(store=store)


# =============================================================================
# Model Tests
# =============================================================================

class TestGovernanceModels:
    """Tests for governance data models."""
    
    def test_risk_scorecard_creation(self):
        """Test creating a risk scorecard."""
        scorecard = RiskScorecard(
            period="quarterly",
            overall_risk_score=0.65,
            risk_level=RiskLevel.HIGH,
            risk_categories={"fraud": 0.7, "cyber": 0.5},
            risk_trend="stable",
        )
        
        assert scorecard.scorecard_id is not None
        assert scorecard.overall_risk_score == 0.65
        assert scorecard.risk_level == RiskLevel.HIGH
    
    def test_compliance_framework_creation(self):
        """Test creating a compliance framework."""
        framework = ComplianceFramework(
            framework_name="SOC2 Type II",
            version="2017",
            status=ComplianceStatus.COMPLIANT,
            compliance_percentage=95.0,
            controls=[],
            findings_count=0,
            open_findings=0,
            critical_findings=0,
        )
        
        assert framework.framework_id is not None
        assert framework.framework_name == "SOC2 Type II"
        assert framework.compliance_percentage == 95.0
    
    def test_audit_finding_creation(self):
        """Test creating an audit finding."""
        finding = AuditFinding(
            finding_title="Test Finding",
            description="Test description",
            severity=AuditFindingSeverity.HIGH,
            category="Access Control",
            risk_impact=0.7,
        )
        
        assert finding.finding_id is not None
        assert finding.finding_title == "Test Finding"
        assert finding.severity == AuditFindingSeverity.HIGH


# =============================================================================
# Store Tests
# =============================================================================

class TestGovernanceStore:
    """Tests for GovernanceStore."""
    
    def test_store_scorecard(self, store):
        """Test storing a scorecard."""
        scorecard = RiskScorecard(
            period="monthly",
            overall_risk_score=0.5,
            risk_level=RiskLevel.MEDIUM,
            risk_categories={"test": 0.5},
            risk_trend="stable",
        )
        
        stored = store.store_scorecard(scorecard)
        retrieved = store.get_scorecard(scorecard.scorecard_id)
        
        assert retrieved is not None
        assert retrieved.overall_risk_score == 0.5
    
    def test_get_latest_scorecard(self, store):
        """Test getting the latest scorecard."""
        scorecard = RiskScorecard(
            period="quarterly",
            overall_risk_score=0.7,
            risk_level=RiskLevel.HIGH,
            risk_categories={"test": 0.7},
            risk_trend="stable",
        )
        store.store_scorecard(scorecard)
        
        latest = store.get_latest_scorecard()
        assert latest is not None
    
    def test_get_all_frameworks(self, store):
        """Test getting all frameworks."""
        frameworks = store.get_all_frameworks()
        assert len(frameworks) >= 3  # Default frameworks
    
    def test_get_open_findings(self, store):
        """Test getting open findings."""
        finding = AuditFinding(
            finding_title="Test",
            description="Test",
            severity=AuditFindingSeverity.HIGH,
            category="Test",
            risk_impact=0.7,
        )
        store.store_finding(finding)
        
        open_findings = store.get_open_findings()
        assert isinstance(open_findings, list)
    
    def test_get_stats(self, store):
        """Test getting store statistics."""
        stats = store.get_stats()
        
        assert "frameworks_stored" in stats
        assert "dashboards_stored" in stats
        assert "reports_stored" in stats


# =============================================================================
# Executive Dashboard Tests
# =============================================================================

class TestExecutiveDashboard:
    """Tests for ExecutiveDashboardModule."""
    
    def test_generate_dashboard(self, dashboard_module):
        """Test generating executive dashboard."""
        dashboard = dashboard_module.generate_dashboard(
            title="Test Dashboard",
            period="weekly",
        )
        
        assert dashboard.dashboard_id is not None
        assert dashboard.title == "Test Dashboard"
        assert len(dashboard.risk_summary) > 0
        assert len(dashboard.compliance_summary) > 0
    
    def test_get_risk_kpis(self, dashboard_module):
        """Test getting risk KPIs."""
        kpis = dashboard_module.get_risk_kpis()
        
        assert "total_risk_exposure" in kpis
        assert "risk_score" in kpis
        assert "risk_level" in kpis
    
    def test_get_compliance_kpis(self, dashboard_module):
        """Test getting compliance KPIs."""
        kpis = dashboard_module.get_compliance_kpis()
        
        assert "overall_compliance" in kpis
        assert "frameworks_count" in kpis
    
    def test_get_performance_kpis(self, dashboard_module):
        """Test getting performance KPIs."""
        kpis = dashboard_module.get_performance_kpis()
        
        assert "investigations_completed" in kpis
        assert "detection_rate" in kpis
    
    def test_get_kpi_summary(self, dashboard_module):
        """Test getting consolidated KPI summary."""
        summary = dashboard_module.get_kpi_summary()
        
        assert "risk_kpis" in summary
        assert "compliance_kpis" in summary
        assert "performance_kpis" in summary


# =============================================================================
# Board Reporting Tests
# =============================================================================

class TestBoardReporting:
    """Tests for BoardReportingModule."""
    
    def test_generate_board_report(self, board_reporting):
        """Test generating board report."""
        now = datetime.now(timezone.utc)
        report = board_reporting.generate_board_report(
            period_start=now - timedelta(days=30),
            period_end=now,
        )
        
        assert report.report_id is not None
        assert report.report_type == ReportType.BOARD_REPORT
    
    def test_generate_executive_summary(self, board_reporting):
        """Test generating executive summary."""
        report = board_reporting.generate_executive_summary(period="monthly")
        
        assert report.report_id is not None
        assert report.report_type == ReportType.EXECUTIVE_SUMMARY
    
    def test_generate_risk_report(self, board_reporting):
        """Test generating risk report."""
        now = datetime.now(timezone.utc)
        report = board_reporting.generate_risk_report(
            period_start=now - timedelta(days=30),
            period_end=now,
        )
        
        assert report.report_id is not None
        assert report.report_type == ReportType.RISK_REPORT
    
    def test_generate_trend_report(self, board_reporting):
        """Test generating trend report."""
        report = board_reporting.generate_trend_report(
            metric_names=["risk_score", "detection_rate"],
            period_days=30,
        )
        
        assert report.report_id is not None
        assert "trend_data" in report.summary
    
    def test_get_board_calendar(self, board_reporting):
        """Test getting board calendar."""
        calendar = board_reporting.get_board_calendar(2026)
        
        assert len(calendar) == 6  # Quarterly reviews + special meetings


# =============================================================================
# Compliance Analytics Tests
# =============================================================================

class TestComplianceAnalytics:
    """Tests for ComplianceAnalyticsModule."""
    
    def test_assess_control(self, compliance_analytics):
        """Test control assessment."""
        assessment = compliance_analytics.assess_control(
            control_id="CC6.1",
            control_name="Logical Access",
            framework="SOC2",
            test_results={"effectiveness_score": 0.85},
        )
        
        assert assessment.assessment_id is not None
        assert assessment.control_id == "CC6.1"
    
    def test_get_framework_status(self, compliance_analytics):
        """Test getting framework status."""
        status = compliance_analytics.get_framework_status("SOC 2")
        
        assert "framework_id" in status or "error" in status
    
    def test_perform_gap_analysis(self, compliance_analytics):
        """Test gap analysis."""
        analysis = compliance_analytics.perform_gap_analysis("SOC 2")
        
        assert "framework" in analysis
        assert "gaps_identified" in analysis
    
    def test_calculate_compliance_score(self, compliance_analytics):
        """Test compliance score calculation."""
        score = compliance_analytics.calculate_compliance_score("SOC 2")
        
        assert 0 <= score <= 100
    
    def test_get_compliance_overview(self, compliance_analytics):
        """Test getting compliance overview."""
        overview = compliance_analytics.get_compliance_overview()
        
        assert "overall_compliance" in overview
        assert "frameworks_tracked" in overview


# =============================================================================
# Risk Governance Tests
# =============================================================================

class TestRiskGovernance:
    """Tests for RiskGovernanceModule."""
    
    def test_generate_risk_scorecard(self, risk_governance):
        """Test generating risk scorecard."""
        scorecard = risk_governance.generate_risk_scorecard(period="monthly")
        
        assert scorecard.scorecard_id is not None
        assert 0 <= scorecard.overall_risk_score <= 1.0
    
    def test_assess_entity_risk(self, risk_governance):
        """Test entity risk assessment."""
        assessment = risk_governance.assess_entity_risk(
            entity_id="entity_1",
            entity_type="account",
            risk_factors={
                "transaction_history": 0.7,
                "device_fingerprint": 0.5,
            },
        )
        
        assert "entity_id" in assessment
        assert "risk_score" in assessment
        assert "risk_level" in assessment
    
    def test_monitor_risk_thresholds(self, risk_governance):
        """Test risk threshold monitoring."""
        thresholds = risk_governance.monitor_risk_thresholds(
            metrics={"risk_score": 0.8},
        )
        
        assert isinstance(thresholds, list)
    
    def test_track_risk_trend(self, risk_governance):
        """Test risk trend tracking."""
        trend = risk_governance.track_risk_trend("risk_score", period_days=30)
        
        assert "current_value" in trend
        assert "trend" in trend
    
    def test_create_risk_threshold(self, risk_governance):
        """Test creating risk threshold."""
        threshold = risk_governance.create_risk_threshold(
            metric_name="risk_score",
            warning_level=0.6,
            critical_level=0.8,
            action_required="Escalate",
        )
        
        assert threshold.threshold_id is not None
        assert threshold.metric_name == "risk_score"
    
    def test_get_risk_summary(self, risk_governance):
        """Test getting risk summary."""
        summary = risk_governance.get_risk_summary()
        
        assert "overall_risk_score" in summary
        assert "risk_level" in summary


# =============================================================================
# Audit Intelligence Tests
# =============================================================================

class TestAuditIntelligence:
    """Tests for AuditIntelligenceModule."""
    
    def test_create_audit_finding(self, audit_intelligence):
        """Test creating audit finding."""
        finding = audit_intelligence.create_audit_finding(
            title="Test Finding",
            description="Test description",
            severity=AuditFindingSeverity.HIGH,
            category="Access Control",
        )
        
        assert finding.finding_id is not None
        assert finding.finding_title == "Test Finding"
    
    def test_update_finding_status(self, audit_intelligence):
        """Test updating finding status."""
        finding = audit_intelligence.create_audit_finding(
            title="Test",
            description="Test",
            severity=AuditFindingSeverity.MEDIUM,
            category="Test",
        )
        
        result = audit_intelligence.update_finding_status(
            finding_id=finding.finding_id,
            new_status="CLOSED",
        )
        
        assert result is True
    
    def test_get_finding_summary(self, audit_intelligence):
        """Test getting finding summary."""
        # Create some findings
        audit_intelligence.create_audit_finding(
            title="Finding 1",
            description="Test",
            severity=AuditFindingSeverity.HIGH,
            category="Test",
        )
        
        summary = audit_intelligence.get_finding_summary()
        
        assert "total_findings" in summary
        assert "open_findings" in summary
    
    def test_track_policy_violation(self, audit_intelligence):
        """Test tracking policy violation."""
        violation = audit_intelligence.track_policy_violation(
            policy_id="POL-001",
            policy_name="Access Control Policy",
            entity_id="entity_1",
            entity_type="account",
            severity=AuditFindingSeverity.MEDIUM,
            description="Unauthorized access attempt",
        )
        
        assert violation.violation_id is not None
    
    def test_get_violation_trends(self, audit_intelligence):
        """Test getting violation trends."""
        trends = audit_intelligence.get_violation_trends(days=30)
        
        assert "total_violations" in trends
        assert "trends" in trends
    
    def test_generate_audit_report(self, audit_intelligence):
        """Test generating audit report."""
        now = datetime.now(timezone.utc)
        report = audit_intelligence.generate_audit_report(
            period_start=now - timedelta(days=30),
            period_end=now,
        )
        
        assert "executive_summary" in report
        assert "finding_summary" in report
    
    def test_get_remediation_status(self, audit_intelligence):
        """Test getting remediation status."""
        status = audit_intelligence.get_remediation_status()
        
        assert "total_open" in status
        assert "on_track" in status
    
    def test_get_audit_calendar(self, audit_intelligence):
        """Test getting audit calendar."""
        calendar = audit_intelligence.get_audit_calendar(2026)
        
        assert len(calendar) > 0


# =============================================================================
# Integration Tests
# =============================================================================

class TestGovernanceIntegration:
    """Integration tests for governance workflow."""
    
    def test_full_governance_workflow(
        self,
        dashboard_module,
        board_reporting,
        risk_governance,
        compliance_analytics,
    ):
        """Test full governance workflow."""
        # 1. Generate dashboard
        dashboard = dashboard_module.generate_dashboard()
        
        # 2. Generate risk scorecard
        scorecard = risk_governance.generate_risk_scorecard()
        
        # 3. Generate board report
        now = datetime.now(timezone.utc)
        report = board_reporting.generate_board_report(
            period_start=now - timedelta(days=30),
            period_end=now,
        )
        
        # 4. Get compliance overview
        overview = compliance_analytics.get_compliance_overview()
        
        # Verify workflow
        assert dashboard.dashboard_id is not None
        assert scorecard.scorecard_id is not None
        assert report.report_id is not None
        assert overview["overall_compliance"] > 0


# =============================================================================
# Performance Tests
# =============================================================================

class TestGovernancePerformance:
    """Performance tests for governance."""
    
    def test_dashboard_generation_performance(self, dashboard_module):
        """Test dashboard generation performance."""
        import time
        
        start = time.time()
        for _ in range(10):
            dashboard_module.generate_dashboard()
        duration = (time.time() - start) * 1000
        
        assert duration < 1000  # 10 dashboards in under 1 second
    
    def test_scorecard_generation_performance(self, risk_governance):
        """Test scorecard generation performance."""
        import time
        
        start = time.time()
        for _ in range(20):
            risk_governance.generate_risk_scorecard()
        duration = (time.time() - start) * 1000
        
        assert duration < 2000  # 20 scorecards in under 2 seconds