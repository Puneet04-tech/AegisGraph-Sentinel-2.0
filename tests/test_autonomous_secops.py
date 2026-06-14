"""
Tests for Autonomous SecOps Platform.
"""

import asyncio
import pytest

from src.autonomous_secops import (
    Alert,
    AlertStatus,
    Incident,
    IncidentStatus,
    Playbook,
    ThreatHunt,
    Severity,
    AutonomousSecOpsStore,
    get_secops_store,
    reset_secops_store,
    SecurityOperationsEngine,
    ThreatCorrelationEngine,
    InvestigationEngine,
    PlaybookEngine,
    ThreatHuntingEngine,
    AutonomousSecOpsService,
)


class TestModels:
    """Test data models."""

    def test_alert_creation(self):
        """Test alert creation."""
        alert = Alert(
            alert_id="alert-1",
            title="Suspicious Login",
            description="Multiple failed login attempts",
            severity=Severity.HIGH,
            source="auth_system",
        )
        assert alert.alert_id == "alert-1"
        assert alert.severity == Severity.HIGH

    def test_incident_creation(self):
        """Test incident creation."""
        incident = Incident(
            incident_id="inc-1",
            title="Data Breach",
            description="Potential data breach detected",
            severity=Severity.CRITICAL,
        )
        assert incident.incident_id == "inc-1"
        assert incident.status == IncidentStatus.NEW


class TestStore:
    """Test SecOps store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_secops_store()
        self.store = get_secops_store()

    def test_add_alert(self):
        """Test adding an alert."""
        alert = Alert(
            alert_id="alert-1",
            title="Test Alert",
            description="Test",
            severity=Severity.MEDIUM,
            source="test",
        )
        self.store.add_alert(alert)
        
        retrieved = self.store.get_alert("alert-1")
        assert retrieved is not None

    def test_create_incident(self):
        """Test creating an incident."""
        incident = Incident(
            incident_id="inc-1",
            title="Test Incident",
            description="Test",
            severity=Severity.HIGH,
        )
        self.store.create_incident(incident)
        
        retrieved = self.store.get_incident("inc-1")
        assert retrieved is not None


class TestSecurityOperationsEngine:
    """Test security operations engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_secops_store()
        self.engine = SecurityOperationsEngine()

    def test_process_alert(self):
        """Test processing an alert."""
        alert = self.engine.process_alert(
            title="Suspicious Activity",
            description="Unusual access pattern",
            severity="high",
            source="siem",
        )
        
        assert alert.alert_id is not None
        assert alert.severity == Severity.HIGH

    def test_triage_alert(self):
        """Test triaging an alert."""
        alert = self.engine.process_alert(
            title="Test Alert",
            description="Test",
            severity="critical",
            source="edr",
        )
        
        result = self.engine.triage_alert(alert.alert_id)
        
        assert result["success"] is True
        assert result["triage_score"] > 0


class TestThreatCorrelation:
    """Test threat correlation engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_secops_store()
        self.engine = ThreatCorrelationEngine()

    def test_add_rule(self):
        """Test adding a correlation rule."""
        rule = self.engine.add_correlation_rule(
            name="High Severity Rule",
            conditions=[{"type": "severity", "value": "critical"}],
            severity="high",
        )
        
        assert rule.rule_id is not None

    def test_evaluate_alerts(self):
        """Test evaluating alerts."""
        self.engine.add_correlation_rule(
            name="Test Rule",
            conditions=[],
            severity="medium",
        )
        
        matches = self.engine.evaluate_alerts()
        assert isinstance(matches, list)


class TestInvestigation:
    """Test investigation engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_secops_store()
        self.engine = InvestigationEngine()
        self.store = get_secops_store()

    def test_start_investigation(self):
        """Test starting an investigation."""
        incident = Incident(
            incident_id="inc-1",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
        )
        self.store.create_incident(incident)
        
        result = self.engine.start_investigation("inc-1")
        
        assert result["success"] is True

    def test_analyze_impact(self):
        """Test impact analysis."""
        incident = Incident(
            incident_id="inc-1",
            title="Test",
            description="Test",
            severity=Severity.CRITICAL,
        )
        self.store.create_incident(incident)
        
        result = self.engine.analyze_impact("inc-1")
        
        assert result["success"] is True


class TestPlaybookEngine:
    """Test playbook engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_secops_store()
        self.engine = PlaybookEngine()

    def test_create_playbook(self):
        """Test creating a playbook."""
        playbook = self.engine.create_playbook(
            name="Malware Response",
            description="Response to malware detection",
            trigger_conditions={"severity": "critical"},
            steps=[
                {"action": "isolate", "target": "affected_host"},
                {"action": "scan", "target": "network"},
            ],
        )
        
        assert playbook.playbook_id is not None

    def test_execute_playbook(self):
        """Test executing a playbook."""
        playbook = self.engine.create_playbook(
            name="Test",
            description="Test",
            trigger_conditions={},
            steps=[{"action": "test"}],
        )
        
        execution = self.engine.execute_playbook(
            playbook.playbook_id,
            "inc-1",
        )
        
        assert execution.execution_id is not None


class TestThreatHunting:
    """Test threat hunting engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_secops_store()
        self.engine = ThreatHuntingEngine()

    def test_create_hunt(self):
        """Test creating a hunt."""
        hunt = self.engine.create_hunt(
            name="Suspicious PowerShell",
            hypothesis="Adversaries use PowerShell for lateral movement",
            created_by="analyst",
        )
        
        assert hunt.hunt_id is not None

    def test_execute_hunt(self):
        """Test executing a hunt."""
        hunt = self.engine.create_hunt(
            name="Test Hunt",
            hypothesis="Testing hypothesis",
            created_by="analyst",
        )
        
        result = self.engine.execute_hunt(hunt.hunt_id)
        
        assert result["success"] is True


class TestAutonomousSecOpsService:
    """Test main service."""

    def setup_method(self):
        """Reset store before each test."""
        reset_secops_store()
        self.service = AutonomousSecOpsService()

    def test_process_alert(self):
        """Test processing an alert."""
        result = asyncio.run(self.service.process_alert(
            title="Test Alert",
            description="Test description",
            severity="high",
            source="siem",
        ))
        
        assert "alert_id" in result
        assert "triage_score" in result

    def test_get_dashboard(self):
        """Test getting dashboard."""
        result = asyncio.run(self.service.get_dashboard())
        
        assert "total_alerts" in result
        assert "total_incidents" in result

    def test_correlate_alerts(self):
        """Test correlating alerts."""
        result = asyncio.run(self.service.correlate_alerts())
        
        assert "matches_count" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])