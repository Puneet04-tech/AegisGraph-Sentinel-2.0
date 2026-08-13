"""
Unit tests for Regulatory Intelligence & Compliance Fabric.
"""

import pytest
from datetime import datetime, timezone, timedelta
from src.regulatory_fabric import (
    get_compliance_store,
    get_intelligence_engine,
    get_drift_detector,
    get_policy_mapper,
    get_evidence_collector,
    get_audit_engine,
    get_control_validator,
    get_risk_engine,
    get_change_tracker,
    get_knowledge_graph,
    get_dashboard_service,
    RegulationDomain,
    ControlStatus,
    Regulation,
    Control,
    ComplianceAssessment,
    AuditEvidence,
    ComplianceRisk,
)


class TestComplianceStore:
    """Tests for ComplianceStore."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_compliance_store()
        # Clear store for clean tests
        self.store.regulations.clear()
        self.store.controls.clear()
        self.store.assessments.clear()

    def test_add_regulation(self):
        """Test adding a regulation."""
        regulation = {
            "domain": "PCI_DSS",
            "name": "PCI DSS 4.0",
            "version": "4.0",
            "description": "Payment Card Industry Data Security Standard",
            "requirements": [
                {"id": "1.1", "name": "Firewall Configuration"},
            ],
        }
        reg_id = self.store.add_regulation(regulation)
        assert reg_id is not None
        
        retrieved = self.store.get_regulation(reg_id)
        assert retrieved is not None
        assert retrieved["name"] == "PCI DSS 4.0"

    def test_list_regulations(self):
        """Test listing regulations."""
        self.store.add_regulation({"domain": "PCI_DSS", "name": "PCI 1"})
        self.store.add_regulation({"domain": "SOC2", "name": "SOC 2"})
        self.store.add_regulation({"domain": "GDPR", "name": "GDPR"})
        
        regulations = self.store.list_regulations()
        assert len(regulations) >= 3
        
        pci_regs = self.store.list_regulations(domain="PCI_DSS")
        assert len(pci_regs) >= 1

    def test_add_control(self):
        """Test adding a control."""
        control = {
            "control_name": "Access Control Policy",
            "control_number": "AC-1",
            "description": "Establish access control policies",
            "category": "Access Control",
            "owner": "Security Team",
        }
        ctrl_id = self.store.add_control(control)
        assert ctrl_id is not None
        
        retrieved = self.store.get_control(ctrl_id)
        assert retrieved is not None
        assert retrieved["control_name"] == "Access Control Policy"

    def test_control_mapping(self):
        """Test control-regulation mapping."""
        reg_id = self.store.add_regulation({
            "domain": "PCI_DSS",
            "name": "PCI DSS",
            "requirements": [{"id": "1.1", "name": "Firewall"}],
        })
        
        ctrl_id = self.store.add_control({
            "control_name": "Firewall Policy",
            "control_number": "FW-1",
        })
        
        mapping = {
            "control_id": ctrl_id,
            "regulation_id": reg_id,
            "requirement_id": "1.1",
            "mapping_type": "DIRECT",
            "justification": "Direct implementation of firewall requirement",
        }
        mapping_id = self.store.add_control_mapping(mapping)
        assert mapping_id is not None
        
        mapped_controls = self.store.get_controls_for_regulation(reg_id)
        assert len(mapped_controls) >= 1

    def test_get_controls_for_regulation_does_not_mutate_persisted_control(self):
        """Reading mapped controls must not attach a mapping to the stored control."""
        reg_id = self.store.add_regulation({
            "domain": "PCI_DSS",
            "name": "PCI DSS",
            "requirements": [{"id": "1.1", "name": "Firewall"}],
        })
        ctrl_id = self.store.add_control({
            "control_name": "Firewall Policy",
            "control_number": "FW-1",
        })
        self.store.add_control_mapping({
            "control_id": ctrl_id,
            "regulation_id": reg_id,
            "requirement_id": "1.1",
            "mapping_type": "DIRECT",
        })

        mapped_controls = self.store.get_controls_for_regulation(reg_id)
        assert len(mapped_controls) == 1
        assert mapped_controls[0]["mapping"]["requirement_id"] == "1.1"

        # The persisted control must be untouched by the read path.
        stored = self.store.get_control(ctrl_id)
        assert "mapping" not in stored

    def test_shared_control_keeps_its_own_mapping_per_regulation(self):
        """A control mapped to two regulations must not exhibit last-mapping-wins."""
        reg_a = self.store.add_regulation({"domain": "PCI_DSS", "name": "PCI DSS"})
        reg_b = self.store.add_regulation({"domain": "SOC2", "name": "SOC 2"})
        ctrl_id = self.store.add_control({
            "control_name": "Shared Access Control",
            "control_number": "AC-1",
        })
        self.store.add_control_mapping({
            "control_id": ctrl_id,
            "regulation_id": reg_a,
            "requirement_id": "PCI-1",
        })
        self.store.add_control_mapping({
            "control_id": ctrl_id,
            "regulation_id": reg_b,
            "requirement_id": "SOC2-2",
        })

        from_reg_a = self.store.get_controls_for_regulation(reg_a)
        from_reg_b = self.store.get_controls_for_regulation(reg_b)

        assert len(from_reg_a) == 1
        assert len(from_reg_b) == 1
        # Each regulation sees its own mapping, not the last one written.
        assert from_reg_a[0]["mapping"]["requirement_id"] == "PCI-1"
        assert from_reg_b[0]["mapping"]["requirement_id"] == "SOC2-2"

        # The persisted control still carries no mapping key.
        assert "mapping" not in self.store.get_control(ctrl_id)

    def test_compliance_score(self):
        """Test compliance score calculation."""
        # Add assessments
        self.store.add_assessment({
            "regulation_id": "test_reg",
            "overall_score": 85.0,
            "status": "COMPLETED",
        })
        self.store.add_assessment({
            "regulation_id": "test_reg2",
            "overall_score": 90.0,
            "status": "COMPLETED",
        })
        
        score = self.store.get_compliance_score()
        assert score == 87.5  # Average of 85 and 90


class TestIntelligenceEngine:
    """Tests for RegulationIntelligenceEngine."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_compliance_store()
        self.store.regulations.clear()
        self.engine = get_intelligence_engine()

    def test_analyze_regulation(self):
        """Test regulation analysis."""
        reg_id = self.store.add_regulation({
            "domain": "PCI_DSS",
            "name": "PCI DSS",
            "requirements": [{"id": "1.1", "name": "Firewall"}],
        })
        
        result = self.engine.analyze_regulation(reg_id)
        assert "regulation_id" in result
        assert result["regulation_id"] == reg_id
        assert "requirements_count" in result

    def test_get_alerts(self):
        """Test getting intelligence alerts."""
        alerts = self.engine.get_alerts()
        assert isinstance(alerts, list)


class TestDriftDetector:
    """Tests for ComplianceDriftDetector."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_compliance_store()
        self.store.controls.clear()
        self.detector = get_drift_detector()

    def test_capture_baseline(self):
        """Test baseline capture."""
        ctrl_id = self.store.add_control({
            "control_name": "Test Control",
            "status": "COMPLIANT",
        })
        
        baseline_id = self.detector.capture_baseline("test_baseline")
        assert baseline_id is not None
        
        baseline = self.detector.get_baseline("test_baseline")
        assert baseline is not None
        assert "controls_state" in baseline.__dict__

    def test_detect_drift_no_change(self):
        """Test drift detection with no changes."""
        ctrl_id = self.store.add_control({
            "control_name": "Stable Control",
            "status": "COMPLIANT",
        })
        
        self.detector.capture_baseline("stable")
        drift_events = self.detector.detect_drift("stable")
        assert isinstance(drift_events, list)


class TestControlValidator:
    """Tests for ControlValidationService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_compliance_store()
        self.store.controls.clear()
        self.validator = get_control_validator()

    def test_validate_control(self):
        """Test control validation."""
        ctrl_id = self.store.add_control({
            "control_name": "Test Control",
            "description": "A test control for validation",
            "implementation": "Implemented according to policy",
            "owner": "Test Owner",
            "test_frequency_days": 30,
        })
        
        result = self.validator.validate_control(ctrl_id)
        assert result is not None
        assert hasattr(result, "validation_id")
        assert hasattr(result, "score")
        assert 0 <= result.score <= 1


class TestRiskEngine:
    """Tests for ComplianceRiskEngine."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_compliance_store()
        self.store.controls.clear()
        self.risk_engine = get_risk_engine()

    def test_assess_control_risk(self):
        """Test control risk assessment."""
        ctrl_id = self.store.add_control({
            "control_name": "Risky Control",
            "status": "NON_COMPLIANT",
            "effectiveness": "INEFFECTIVE",
        })
        
        risk = self.risk_engine.assess_risk("control", ctrl_id)
        assert risk is not None
        assert risk["risk_score"] >= 0  # Should have elevated risk

    def test_portfolio_risk(self):
        """Test portfolio risk assessment."""
        result = self.risk_engine.get_portfolio_risk()
        assert "portfolio_risk_score" in result
        assert "risk_distribution" in result


class TestDashboardService:
    """Tests for ComplianceDashboardService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.dashboard = get_dashboard_service()

    def test_generate_dashboard(self):
        """Test dashboard generation."""
        dashboard = self.dashboard.generate_dashboard()
        assert dashboard is not None
        assert hasattr(dashboard, "overall_score")
        assert hasattr(dashboard, "domain_scores")
        assert hasattr(dashboard, "trend_direction")

    def test_trend_direction_mixed_datetime_and_iso_dates(self):
        """Trend calculation must handle datetime and ISO string dates."""
        from src.regulatory_fabric.dashboard import ComplianceDashboardService
        from src.regulatory_fabric.store import ComplianceStore

        store = ComplianceStore()
        now = datetime.now(timezone.utc)

        store.add_assessment({
            "assessment_id": "assess_recent_datetime",
            "overall_score": 92.0,
            "assessment_date": now,
            "status": "COMPLETED",
        })
        store.add_assessment({
            "assessment_id": "assess_recent_iso",
            "overall_score": 88.0,
            "assessment_date": (now - timedelta(days=10)).isoformat(),
            "status": "COMPLETED",
        })
        store.add_assessment({
            "assessment_id": "assess_old_iso",
            "overall_score": 60.0,
            "assessment_date": (now - timedelta(days=90)).isoformat(),
            "status": "COMPLETED",
        })

        service = ComplianceDashboardService(store, None, None, None)
        dashboard = service.generate_dashboard()
        assert dashboard.trend_direction == "IMPROVING"

    def test_trend_direction_missing_dates_are_skipped(self):
        """Assessments without a parseable date must not crash the trend."""
        from src.regulatory_fabric.dashboard import ComplianceDashboardService
        from src.regulatory_fabric.store import ComplianceStore

        store = ComplianceStore()
        now = datetime.now(timezone.utc)

        store.add_assessment({
            "assessment_id": "assess_no_date",
            "overall_score": 90.0,
            "status": "COMPLETED",
        })
        store.add_assessment({
            "assessment_id": "assess_recent",
            "overall_score": 95.0,
            "assessment_date": now,
            "status": "COMPLETED",
        })
        store.add_assessment({
            "assessment_id": "assess_old",
            "overall_score": 70.0,
            "assessment_date": (now - timedelta(days=60)).isoformat(),
            "status": "COMPLETED",
        })

        service = ComplianceDashboardService(store, None, None, None)
        dashboard = service.generate_dashboard()
        assert dashboard.trend_direction == "IMPROVING"

    def test_trend_direction_naive_datetime_is_handled(self):
        """Naive datetimes must be treated as UTC, not crash the comparison."""
        from src.regulatory_fabric.dashboard import ComplianceDashboardService
        from src.regulatory_fabric.store import ComplianceStore

        store = ComplianceStore()
        now = datetime.now(timezone.utc)

        store.add_assessment({
            "assessment_id": "assess_recent_naive",
            "overall_score": 94.0,
            "assessment_date": now.replace(tzinfo=None),
            "status": "COMPLETED",
        })
        store.add_assessment({
            "assessment_id": "assess_old_naive",
            "overall_score": 55.0,
            "assessment_date": (now - timedelta(days=120)).replace(tzinfo=None),
            "status": "COMPLETED",
        })

        service = ComplianceDashboardService(store, None, None, None)
        dashboard = service.generate_dashboard()
        assert dashboard.trend_direction == "IMPROVING"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])