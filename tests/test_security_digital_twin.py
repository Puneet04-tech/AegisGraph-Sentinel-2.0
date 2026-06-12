"""
Tests for Security Digital Twin Platform.
"""

import pytest

from src.security_digital_twin import (
    AssetType,
    DigitalTwinAsset,
    RiskLevel,
    SimulationScenario,
    SimulationType,
    ThreatSimulation,
    DigitalTwinStore,
    get_twin_store,
    reset_twin_store,
    DigitalTwinEngine,
)


class TestModels:
    """Test data models."""

    def test_asset_creation(self):
        """Test asset creation."""
        asset = DigitalTwinAsset(
            asset_id="asset-1",
            asset_type=AssetType.ENDPOINT,
            name="Workstation 1",
        )
        assert asset.asset_id == "asset-1"
        assert asset.asset_type == AssetType.ENDPOINT

    def test_scenario_creation(self):
        """Test scenario creation."""
        scenario = SimulationScenario(
            scenario_id="scenario-1",
            name="Ransomware Attack",
            simulation_type=SimulationType.THREAT,
            description="Simulate ransomware attack",
        )
        assert scenario.scenario_id == "scenario-1"


class TestStore:
    """Test digital twin store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_twin_store()
        self.store = get_twin_store()

    def test_add_asset(self):
        """Test adding an asset."""
        asset = DigitalTwinAsset(
            asset_id="asset-1",
            asset_type=AssetType.SERVER,
            name="Server 1",
        )
        self.store.add_asset(asset)
        
        retrieved = self.store.get_asset("asset-1")
        assert retrieved is not None


class TestDigitalTwinEngine:
    """Test digital twin engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_twin_store()
        self.engine = DigitalTwinEngine()

    def test_add_asset(self):
        """Test adding an asset."""
        asset = self.engine.add_asset(
            asset_type="endpoint",
            name="Test Workstation",
        )
        
        assert asset.asset_id is not None
        assert asset.asset_type == AssetType.ENDPOINT

    def test_create_scenario(self):
        """Test creating a scenario."""
        scenario = self.engine.create_scenario(
            name="Phishing Attack",
            simulation_type="threat",
            description="Simulate phishing attack",
        )
        
        assert scenario.scenario_id is not None

    def test_run_threat_simulation(self):
        """Test running threat simulation."""
        scenario = self.engine.create_scenario(
            name="Test",
            simulation_type="threat",
            description="Test",
        )
        
        simulation = self.engine.run_threat_simulation(
            scenario_id=scenario.scenario_id,
            threat_type="ransomware",
            initial_conditions={"target": "server1"},
        )
        
        assert simulation.simulation_id is not None
        assert simulation.success_probability > 0

    def test_run_fraud_simulation(self):
        """Test running fraud simulation."""
        scenario = self.engine.create_scenario(
            name="Test",
            simulation_type="fraud",
            description="Test",
        )
        
        simulation = self.engine.run_fraud_simulation(
            scenario_id=scenario.scenario_id,
            fraud_type="mule_account",
            accounts=["acc1", "acc2"],
        )
        
        assert simulation.simulation_id is not None

    def test_analyze_attack_path(self):
        """Test analyzing attack path."""
        path = self.engine.analyze_attack_path(
            source_asset="workstation1",
            target_asset="database1",
        )
        
        assert path.path_id is not None
        assert path.overall_risk > 0

    def test_forecast_risk(self):
        """Test forecasting risk."""
        forecast = self.engine.forecast_risk(
            metric_type="ransomware_risk",
            current_value=0.5,
            time_horizon_days=30,
        )
        
        assert forecast.forecast_id is not None
        assert forecast.forecasted_value > forecast.current_value

    def test_assess_impact(self):
        """Test assessing impact."""
        scenario = self.engine.create_scenario(
            name="Test",
            simulation_type="threat",
            description="Test",
        )
        
        assessment = self.engine.assess_impact(
            scenario_id=scenario.scenario_id,
            affected_assets=["server1", "server2"],
        )
        
        assert assessment.assessment_id is not None

    def test_get_dashboard(self):
        """Test getting dashboard."""
        result = self.engine.get_dashboard()
        
        assert "total_assets" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])