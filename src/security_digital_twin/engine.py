"""
Security Digital Twin Engine.

Main service for security digital twin operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    AssetType,
    AttackPath,
    DigitalTwinAsset,
    FraudSimulation,
    ImpactAssessment,
    RiskForecast,
    SimulationScenario,
    SimulationStatus,
    SimulationType,
    ThreatSimulation,
)
from .store import DigitalTwinStore, get_twin_store


class DigitalTwinEngine:
    """Main digital twin engine."""

    def __init__(self, store: Optional[DigitalTwinStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_twin_store()

    def add_asset(
        self,
        asset_type: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None,
        vulnerabilities: Optional[List[str]] = None,
    ) -> DigitalTwinAsset:
        """Add an asset to the twin."""
        asset_id = f"asset-{uuid.uuid4().hex[:12]}"
        
        asset = DigitalTwinAsset(
            asset_id=asset_id,
            asset_type=AssetType(asset_type),
            name=name,
            properties=properties or {},
            vulnerabilities=vulnerabilities or [],
        )
        
        self.store.add_asset(asset)
        
        self.store.log_audit(
            user_id="system",
            action="asset_added",
            resource_type="digital_twin_asset",
            resource_id=asset_id,
            details={"type": asset_type, "name": name},
        )
        
        return asset

    def create_scenario(
        self,
        name: str,
        simulation_type: str,
        description: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> SimulationScenario:
        """Create a simulation scenario."""
        scenario_id = f"scenario-{uuid.uuid4().hex[:12]}"
        
        scenario = SimulationScenario(
            scenario_id=scenario_id,
            name=name,
            simulation_type=SimulationType(simulation_type),
            description=description,
            parameters=parameters or {},
        )
        
        self.store.add_scenario(scenario)
        
        return scenario

    def run_threat_simulation(
        self,
        scenario_id: str,
        threat_type: str,
        initial_conditions: Dict[str, Any],
    ) -> ThreatSimulation:
        """Run a threat simulation."""
        scenario = self.store.get_scenario(scenario_id)
        if scenario:
            scenario.status = SimulationStatus.RUNNING
        
        simulation_id = f"threat-{uuid.uuid4().hex[:12]}"
        
        attack_steps = self._simulate_attack_steps(threat_type, initial_conditions)
        
        simulation = ThreatSimulation(
            simulation_id=simulation_id,
            scenario_id=scenario_id,
            threat_type=threat_type,
            initial_conditions=initial_conditions,
            attack_steps=attack_steps,
            success_probability=self._calculate_success_probability(attack_steps),
            impact_score=self._calculate_impact_score(attack_steps),
            mitigation_recommendations=self._generate_mitigations(threat_type),
        )
        
        self.store.add_threat_simulation(simulation)
        
        if scenario:
            scenario.status = SimulationStatus.COMPLETED
        
        self.store.log_audit(
            user_id="system",
            action="threat_simulation_run",
            resource_type="threat_simulation",
            resource_id=simulation_id,
        )
        
        return simulation

    def _simulate_attack_steps(
        self,
        threat_type: str,
        conditions: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Simulate attack steps."""
        steps = []
        
        if threat_type in ["ransomware", "malware"]:
            steps.append({"step": 1, "action": "initial_access", "status": "success"})
            steps.append({"step": 2, "action": "execution", "status": "success"})
            steps.append({"step": 3, "action": "persistence", "status": "success"})
            steps.append({"step": 4, "action": "impact", "status": "success"})
        
        return steps

    def _calculate_success_probability(self, steps: List[Dict[str, Any]]) -> float:
        """Calculate success probability."""
        if not steps:
            return 0.0
        
        success_count = sum(1 for s in steps if s.get("status") == "success")
        return success_count / len(steps)

    def _calculate_impact_score(self, steps: List[Dict[str, Any]]) -> float:
        """Calculate impact score."""
        return min(1.0, len(steps) * 0.25)

    def _generate_mitigations(self, threat_type: str) -> List[str]:
        """Generate mitigation recommendations."""
        mitigations = {
            "ransomware": [
                "Implement backup strategy",
                "Enable endpoint detection",
                "Patch vulnerable systems",
            ],
            "phishing": [
                "Deploy email filtering",
                "Implement user training",
                "Enable MFA",
            ],
        }
        return mitigations.get(threat_type, ["Apply security best practices"])

    def run_fraud_simulation(
        self,
        scenario_id: str,
        fraud_type: str,
        accounts: List[str],
    ) -> FraudSimulation:
        """Run a fraud simulation."""
        simulation_id = f"fraud-{uuid.uuid4().hex[:12]}"
        
        simulation = FraudSimulation(
            simulation_id=simulation_id,
            scenario_id=scenario_id,
            fraud_type=fraud_type,
            fraud_pattern=f"pattern_{fraud_type}",
            accounts_involved=accounts,
            financial_impact=len(accounts) * 5000.0,
            detection_likelihood=0.7,
            prevention_effectiveness=0.8,
            recommendations=["Monitor transaction patterns", "Implement ML detection"],
        )
        
        self.store.add_fraud_simulation(simulation)
        
        return simulation

    def analyze_attack_path(
        self,
        source_asset: str,
        target_asset: str,
    ) -> AttackPath:
        """Analyze attack path."""
        path_id = f"path-{uuid.uuid4().hex[:12]}"
        
        path = AttackPath(
            path_id=path_id,
            source_asset=source_asset,
            target_asset=target_asset,
            attack_steps=[
                {"step": 1, "from": source_asset, "to": "intermediate_1", "technique": "phishing"},
                {"step": 2, "from": "intermediate_1", "to": target_asset, "technique": "lateral_movement"},
            ],
            overall_risk=0.75,
            mitigation_points=["network_segmentation", "mfa", "monitoring"],
        )
        
        self.store.add_attack_path(path)
        
        return path

    def forecast_risk(
        self,
        metric_type: str,
        current_value: float,
        time_horizon_days: int = 30,
    ) -> RiskForecast:
        """Forecast risk."""
        forecast_id = f"forecast-{uuid.uuid4().hex[:12]}"
        
        growth_factor = 1.0 + (time_horizon_days / 365.0) * 0.1
        forecasted = min(1.0, current_value * growth_factor)
        
        forecast = RiskForecast(
            forecast_id=forecast_id,
            metric_type=metric_type,
            current_value=current_value,
            forecasted_value=forecasted,
            confidence=0.75,
            time_horizon_days=time_horizon_days,
            factors=["historical_trend", "threat_intelligence", "vulnerability_data"],
        )
        
        self.store.store_forecast(forecast)
        
        return forecast

    def assess_impact(
        self,
        scenario_id: str,
        affected_assets: List[str],
    ) -> ImpactAssessment:
        """Assess impact of a scenario."""
        assessment_id = f"impact-{uuid.uuid4().hex[:12]}"
        
        assessment = ImpactAssessment(
            assessment_id=assessment_id,
            scenario_id=scenario_id,
            affected_assets=affected_assets,
            financial_impact=len(affected_assets) * 10000.0,
            operational_impact=0.6,
            reputational_impact=0.5,
            overall_impact_score=0.55,
            recommendations=["Implement controls", "Enhance monitoring"],
        )
        
        self.store.add_assessment(assessment)
        
        return assessment

    def get_dashboard(self) -> Dict[str, Any]:
        """Get dashboard."""
        metrics = self.store.get_dashboard_metrics()
        
        return {
            **metrics,
            "simulations_executed": metrics["threat_simulations"] + metrics["fraud_simulations"],
        }

    def get_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log."""
        events = self.store.get_audit_log(limit)
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "resource_type": e.resource_type,
            }
            for e in events
        ]


# Singleton instance
_engine: Optional[DigitalTwinEngine] = None


def get_twin_engine() -> DigitalTwinEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = DigitalTwinEngine()
    return _engine


def reset_twin_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None