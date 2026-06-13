"""
Tests for Fraud Intelligence Research Center
"""

import pytest

from src.research_center.models import (
    ResearchProject,
    Experiment,
    SimulationScenario,
    ThreatPattern,
    ProjectStatus,
    ExperimentStatus,
)
from src.research_center.store import get_research_center_store, reset_research_center_store
from src.research_center.service import ResearchCenterService


class TestResearchCenterModels:
    """Tests for research center models."""

    def test_create_project(self):
        """Test creating a research project."""
        project = ResearchProject(
            name="Fraud Pattern Analysis",
            description="Analyze emerging fraud patterns",
            hypothesis="New fraud patterns are emerging in mobile transactions",
        )
        assert project.name == "Fraud Pattern Analysis"
        assert project.status == ProjectStatus.DRAFT

    def test_create_experiment(self):
        """Test creating an experiment."""
        experiment = Experiment(
            project_id="project-001",
            name="Test Experiment",
            description="Test hypothesis",
        )
        assert experiment.status == ExperimentStatus.PROPOSED

    def test_create_scenario(self):
        """Test creating a simulation scenario."""
        scenario = SimulationScenario(
            name="Account Takeover",
            description="Simulate account takeover attack",
            attack_type="credential_stuffing",
        )
        assert scenario.attack_type == "credential_stuffing"

    def test_create_pattern(self):
        """Test creating a threat pattern."""
        pattern = ThreatPattern(
            name="New Phishing Kit",
            category="phishing",
            description="Emerging phishing techniques",
            indicators=["suspicious_domain", "fake_login"],
        )
        assert len(pattern.indicators) == 2


class TestResearchCenterStore:
    """Tests for research center store."""

    def setup_method(self):
        """Set up test store."""
        reset_research_center_store()
        self.store = get_research_center_store()

    def test_store_project(self):
        """Test storing a project."""
        project = ResearchProject(
            name="Test",
            description="Test",
            hypothesis="Test",
        )
        self.store.store_project(project)
        retrieved = self.store.get_project(project.project_id)
        assert retrieved is not None

    def test_store_experiment(self):
        """Test storing an experiment."""
        experiment = Experiment(
            project_id="project-001",
            name="Test",
            description="Test",
        )
        self.store.store_experiment(experiment)
        retrieved = self.store.get_experiment(experiment.experiment_id)
        assert retrieved is not None

    def test_store_scenario(self):
        """Test storing a scenario."""
        scenario = SimulationScenario(
            name="Test",
            description="Test",
            attack_type="test",
        )
        self.store.store_scenario(scenario)
        retrieved = self.store.get_scenario(scenario.scenario_id)
        assert retrieved is not None

    def test_store_pattern(self):
        """Test storing a pattern."""
        pattern = ThreatPattern(
            name="Test",
            category="test",
            description="Test",
            indicators=[],
        )
        self.store.store_pattern(pattern)
        retrieved = self.store.get_pattern(pattern.pattern_id)
        assert retrieved is not None

    def test_get_metrics(self):
        """Test getting metrics."""
        self.store.store_project(ResearchProject(
            name="Test",
            description="Test",
            hypothesis="Test",
            status=ProjectStatus.ACTIVE,
        ))
        metrics = self.store.get_metrics()
        assert "active_projects" in metrics


class TestResearchCenterService:
    """Tests for research center service."""

    def setup_method(self):
        """Set up test service."""
        reset_research_center_store()
        self.service = ResearchCenterService()

    def test_create_project(self):
        """Test creating a project."""
        project = self.service.create_project(
            name="Fraud Research",
            description="Research fraud patterns",
            hypothesis="Test hypothesis",
        )
        assert project.project_id is not None

    def test_update_project_status(self):
        """Test updating project status."""
        project = self.service.create_project(
            name="Test",
            description="Test",
            hypothesis="Test",
        )
        updated = self.service.update_project_status(
            project.project_id,
            ProjectStatus.ACTIVE,
        )
        assert updated is not None
        assert updated.status == ProjectStatus.ACTIVE

    def test_create_experiment(self):
        """Test creating an experiment."""
        project = self.service.create_project(
            name="Test",
            description="Test",
            hypothesis="Test",
        )
        experiment = self.service.create_experiment(
            project_id=project.project_id,
            name="Test Experiment",
            description="Test",
        )
        assert experiment is not None

    def test_run_experiment(self):
        """Test running an experiment."""
        project = self.service.create_project(
            name="Test",
            description="Test",
            hypothesis="Test",
        )
        experiment = self.service.create_experiment(
            project_id=project.project_id,
            name="Test",
            description="Test",
        )
        results = {"accuracy": 0.95, "precision": 0.92}
        completed = self.service.run_experiment(
            experiment.experiment_id,
            results,
        )
        assert completed is not None
        assert completed.status == ExperimentStatus.COMPLETED

    def test_identify_pattern(self):
        """Test identifying a threat pattern."""
        pattern = self.service.identify_threat_pattern(
            name="New Attack",
            category="malware",
            description="New malware variant",
            indicators=["file_hash", "network_behavior"],
        )
        assert pattern.pattern_id is not None

    def test_create_profile(self):
        """Test creating a behavior profile."""
        profile = self.service.create_profile(
            entity_type="user",
            entity_id="user-001",
        )
        assert profile.profile_id is not None

    def test_add_finding(self):
        """Test adding a finding."""
        project = self.service.create_project(
            name="Test",
            description="Test",
            hypothesis="Test",
        )
        finding = self.service.add_finding(
            project_id=project.project_id,
            title="Key Finding",
            description="Important discovery",
            confidence=0.9,
        )
        assert finding is not None

    def test_get_metrics(self):
        """Test getting metrics."""
        self.service.create_project(
            name="Test",
            description="Test",
            hypothesis="Test",
        )
        metrics = self.service.get_metrics()
        assert metrics.total_projects >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
