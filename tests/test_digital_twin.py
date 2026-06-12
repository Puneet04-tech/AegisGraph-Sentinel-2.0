"""
Tests for Digital Twin Platform Module
"""
import pytest
from datetime import datetime, timezone

from src.digital_twin import (
    DigitalTwinEngine,
    get_digital_twin_engine,
    SimulationManager,
    ScenarioBuilder,
    ThreatModelingEngine,
    RiskImpactAnalyzer,
    DigitalTwin,
    TwinType,
    Simulation,
    SimulationStatus,
    Scenario,
    ScenarioType,
    RiskAnalysis,
)


class TestDigitalTwinEngine:
    """Tests for DigitalTwinEngine."""
    
    def setup_method(self):
        self.engine = DigitalTwinEngine()
    
    def test_create_twin(self):
        """Test creating a twin."""
        twin_id = self.engine.create_twin(
            name="Test Twin",
            twin_type=TwinType.FRAUD_ECOSYSTEM,
        )
        
        assert twin_id is not None
        assert self.engine.get_twin(twin_id) is not None
    
    def test_get_twin(self):
        """Test getting a twin."""
        twin_id = self.engine.create_twin("Test", TwinType.CYBER_NETWORK)
        
        twin = self.engine.get_twin(twin_id)
        assert twin is not None
        assert twin.twin_id == twin_id
    
    def test_update_twin(self):
        """Test updating a twin."""
        twin_id = self.engine.create_twin("Test", TwinType.FRAUD_ECOSYSTEM)
        
        success = self.engine.update_twin(
            twin_id=twin_id,
            metrics={"test_metric": 1.0},
        )
        
        assert success is True
        twin = self.engine.get_twin(twin_id)
        assert twin.metrics.get("test_metric") == 1.0
    
    def test_simulate(self):
        """Test running a simulation."""
        twin_id = self.engine.create_twin("Test", TwinType.FRAUD_ECOSYSTEM)
        
        simulation_id = self.engine.simulate(
            twin_id=twin_id,
            scenario_id="sc-001",
        )
        
        assert simulation_id is not None
    
    def test_get_dashboard(self):
        """Test getting dashboard."""
        twin_id = self.engine.create_twin("Test", TwinType.FRAUD_ECOSYSTEM)
        
        dashboard = self.engine.get_dashboard(twin_id)
        
        assert "twin_id" in dashboard
        assert "entity_count" in dashboard


class TestSimulationManager:
    """Tests for SimulationManager."""
    
    def setup_method(self):
        self.manager = SimulationManager()
    
    def test_create_simulation(self):
        """Test creating a simulation."""
        sim_id = self.manager.create_simulation(
            twin_id="twin-1",
            scenario_type=ScenarioType.ATTACK_SIMULATION,
        )
        
        assert sim_id is not None
        assert self.manager.get_simulation(sim_id) is not None
    
    def test_start_simulation(self):
        """Test starting a simulation."""
        sim_id = self.manager.create_simulation(
            twin_id="twin-1",
            scenario_type=ScenarioType.FRAUD_SCENARIO,
        )
        
        success = self.manager.start_simulation(sim_id)
        assert success is True
        
        sim = self.manager.get_simulation(sim_id)
        assert sim.status == SimulationStatus.RUNNING
    
    def test_complete_simulation(self):
        """Test completing a simulation."""
        sim_id = self.manager.create_simulation(
            twin_id="twin-1",
            scenario_type=ScenarioType.RISK_ASSESSMENT,
        )
        
        self.manager.start_simulation(sim_id)
        
        success = self.manager.complete_simulation(
            sim_id,
            results={"outcome": "success"},
        )
        
        assert success is True
        sim = self.manager.get_simulation(sim_id)
        assert sim.status == SimulationStatus.COMPLETED


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
            description="Test description",
            scenario_type=ScenarioType.ATTACK_SIMULATION,
            twin_type=TwinType.CYBER_NETWORK,
            steps=[{"step": 1, "action": "test"}],
            expected_outcomes=["success"],
        )
        
        assert scenario_id is not None
        assert self.builder.get_scenario(scenario_id) is not None
    
    def test_get_scenarios_by_type(self):
        """Test getting scenarios by type."""
        scenarios = self.builder.get_scenarios_by_type(ScenarioType.ATTACK_SIMULATION)
        assert len(scenarios) >= 1


class TestThreatModelingEngine:
    """Tests for ThreatModelingEngine."""
    
    def setup_method(self):
        self.engine = ThreatModelingEngine()
    
    def test_create_threat_model(self):
        """Test creating a threat model."""
        model_id = self.engine.create_threat_model(
            twin_id="twin-1",
            threat_scenario={"attack_types": ["phishing", "malware"]},
        )
        
        assert model_id is not None
    
    def test_evaluate_risk(self):
        """Test evaluating risk."""
        result = self.engine.evaluate_risk(twin_id="twin-1")
        
        assert "risk_score" in result
        assert result["risk_score"] >= 0


class TestRiskImpactAnalyzer:
    """Tests for RiskImpactAnalyzer."""
    
    def setup_method(self):
        self.analyzer = RiskImpactAnalyzer()
    
    def test_analyze(self):
        """Test risk analysis."""
        analysis = self.analyzer.analyze(
            twin_id="twin-1",
            affected_entities=["e1", "e2", "e3"],
            threat_level=0.8,
        )
        
        assert analysis is not None
        assert analysis.risk_score > 0


class TestModels:
    """Tests for model classes."""
    
    def test_digital_twin_to_dict(self):
        """Test DigitalTwin serialization."""
        twin = DigitalTwin(
            twin_id="test-1",
            name="Test Twin",
            twin_type=TwinType.FRAUD_ECOSYSTEM,
        )
        
        data = twin.to_dict()
        assert data["twin_id"] == "test-1"
        assert data["twin_type"] == "FRAUD_ECOSYSTEM"
    
    def test_twin_type_values(self):
        """Test TwinType enum."""
        assert TwinType.FRAUD_ECOSYSTEM.value == "FRAUD_ECOSYSTEM"
        assert TwinType.CYBER_NETWORK.value == "CYBER_NETWORK"
    
    def test_simulation_status_values(self):
        """Test SimulationStatus enum."""
        assert SimulationStatus.READY.value == "READY"
        assert SimulationStatus.RUNNING.value == "RUNNING"
    
    def test_scenario_type_values(self):
        """Test ScenarioType enum."""
        assert ScenarioType.ATTACK_SIMULATION.value == "ATTACK_SIMULATION"
        assert ScenarioType.FRAUD_SCENARIO.value == "FRAUD_SCENARIO"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])