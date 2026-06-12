"""
Tests for Threat Simulation Environment Module
"""
import pytest
from datetime import datetime, timezone

from src.threat_simulation import (
    ThreatSimulator,
    get_threat_simulator,
    AdversaryModelingEngine,
    ScenarioBuilder,
    SimulationAnalytics,
    ThreatActor,
    AttackType,
    AttackScenario,
    SimulationRun,
    SimulationRunStatus,
)


class TestAdversaryModelingEngine:
    """Tests for AdversaryModelingEngine."""
    
    def setup_method(self):
        self.engine = AdversaryModelingEngine()
    
    def test_initialization(self):
        """Test engine initialization."""
        assert len(self.engine.actors) > 0
    
    def test_create_actor(self):
        """Test creating a threat actor."""
        actor_id = self.engine.create_actor(
            name="Test Actor",
            sophistication="HIGH",
            motivation="Test",
            capabilities=["test-capability"],
            targets=["test-target"],
        )
        
        assert actor_id is not None
        assert self.engine.get_actor(actor_id) is not None
    
    def test_get_actor(self):
        """Test getting a threat actor."""
        actor_id = self.engine.create_actor(
            name="Get Test",
            sophistication="MEDIUM",
            motivation="Test",
            capabilities=["test"],
            targets=["financial"],
        )
        
        actor = self.engine.get_actor(actor_id)
        assert actor is not None
        assert actor.name == "Get Test"
    
    def test_get_actors_by_target(self):
        """Test getting actors by target."""
        actors = self.engine.get_actors_by_target("financial")
        assert len(actors) >= 1


class TestScenarioBuilder:
    """Tests for ScenarioBuilder."""
    
    def setup_method(self):
        self.builder = ScenarioBuilder()
    
    def test_initialization(self):
        """Test builder initialization."""
        assert len(self.builder.scenarios) > 0
    
    def test_create_scenario(self):
        """Test creating a scenario."""
        scenario_id = self.builder.create_scenario(
            name="Test Scenario",
            attack_type=AttackType.PHISHING,
            description="Test description",
            steps=[{"step": 1, "action": "test"}],
        )
        
        assert scenario_id is not None
        assert self.builder.get_scenario(scenario_id) is not None
    
    def test_get_scenario(self):
        """Test getting a scenario."""
        scenario = self.builder.get_scenario("asc-001")
        assert scenario is not None
        assert scenario.name == "Phishing Campaign"


class TestThreatSimulator:
    """Tests for ThreatSimulator."""
    
    def setup_method(self):
        self.simulator = ThreatSimulator()
    
    def test_start_simulation(self):
        """Test starting a simulation."""
        run_id = self.simulator.start_simulation(
            scenario_id="asc-001",
            actor_id="actor-001",
        )
        
        assert run_id is not None
        assert self.simulator.get_run(run_id) is not None
    
    def test_execute_step(self):
        """Test executing a step."""
        run_id = self.simulator.start_simulation(
            scenario_id="asc-001",
            actor_id="actor-001",
        )
        
        event = self.simulator.execute_step(
            run_id=run_id,
            step={"step": 1, "action": "test", "duration": 60},
        )
        
        assert event is not None
        assert "outcome" in event
    
    def test_complete_simulation(self):
        """Test completing a simulation."""
        run_id = self.simulator.start_simulation(
            scenario_id="asc-002",
            actor_id="actor-002",
        )
        
        success = self.simulator.complete_simulation(
            run_id=run_id,
            results={"outcome": "success"},
        )
        
        assert success is True
        run = self.simulator.get_run(run_id)
        assert run.status == SimulationRunStatus.COMPLETED
    
    def test_get_runs_by_scenario(self):
        """Test getting runs by scenario."""
        self.simulator.start_simulation("asc-001", "actor-001")
        self.simulator.start_simulation("asc-001", "actor-002")
        
        runs = self.simulator.get_runs_by_scenario("asc-001")
        assert len(runs) >= 2
    
    def test_evaluate_threat(self):
        """Test evaluating threat."""
        run_id = self.simulator.start_simulation(
            scenario_id="asc-001",
            actor_id="actor-001",
        )
        
        self.simulator.execute_step(run_id, {"step": 1, "action": "test"})
        self.simulator.complete_simulation(run_id)
        
        evaluation = self.simulator.evaluate_threat(run_id)
        
        assert evaluation is not None
        assert evaluation.threat_score >= 0


class TestSimulationAnalytics:
    """Tests for SimulationAnalytics."""
    
    def setup_method(self):
        self.simulator = ThreatSimulator()
        self.analytics = SimulationAnalytics(self.simulator)
    
    def test_run_analytics(self):
        """Test running analytics."""
        run_id = self.simulator.start_simulation("asc-001", "actor-001")
        self.simulator.complete_simulation(run_id)
        
        result = self.analytics.run_analytics(run_id)
        
        assert "evaluation_id" in result
        assert "threat_score" in result
    
    def test_get_summary_report(self):
        """Test getting summary report."""
        report = self.analytics.get_summary_report()
        
        assert "total_evaluations" in report


class TestModels:
    """Tests for model classes."""
    
    def test_threat_actor_to_dict(self):
        """Test ThreatActor serialization."""
        actor = ThreatActor(
            actor_id="test-1",
            name="Test Actor",
            sophistication="HIGH",
            motivation="Test",
            capabilities=["test"],
            targets=["test"],
        )
        
        data = actor.to_dict()
        assert data["actor_id"] == "test-1"
        assert data["sophistication"] == "HIGH"
    
    def test_attack_type_values(self):
        """Test AttackType enum."""
        assert AttackType.PHISHING.value == "PHISHING"
        assert AttackType.MALWARE.value == "MALWARE"
        assert len(AttackType) > 0
    
    def test_simulation_run_status_values(self):
        """Test SimulationRunStatus enum."""
        assert SimulationRunStatus.PENDING.value == "PENDING"
        assert SimulationRunStatus.RUNNING.value == "RUNNING"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])