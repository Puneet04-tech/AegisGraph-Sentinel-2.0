"""
Digital Twin Engine
Enterprise ecosystem simulation and analysis.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
import random

from .models import (
    DigitalTwin,
    TwinType,
    Simulation,
    SimulationStatus,
    Scenario,
    ScenarioType,
    RiskAnalysis,
)


class SimulationManager:
    """Manager for simulations."""
    
    def __init__(self):
        self.simulations: Dict[str, Simulation] = {}
    
    def create_simulation(
        self,
        twin_id: str,
        scenario_type: ScenarioType,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a new simulation."""
        simulation_id = str(uuid4())
        
        simulation = Simulation(
            simulation_id=simulation_id,
            twin_id=twin_id,
            scenario_type=scenario_type,
            parameters=parameters or {},
        )
        
        self.simulations[simulation_id] = simulation
        return simulation_id
    
    def start_simulation(self, simulation_id: str) -> bool:
        """Start a simulation."""
        simulation = self.simulations.get(simulation_id)
        if not simulation:
            return False
        
        simulation.status = SimulationStatus.RUNNING
        simulation.start_time = datetime.now(timezone.utc)
        return True
    
    def complete_simulation(
        self,
        simulation_id: str,
        results: Dict[str, Any],
    ) -> bool:
        """Complete a simulation."""
        simulation = self.simulations.get(simulation_id)
        if not simulation:
            return False
        
        simulation.status = SimulationStatus.COMPLETED
        simulation.end_time = datetime.now(timezone.utc)
        simulation.results = results
        return True
    
    def get_simulation(self, simulation_id: str) -> Optional[Simulation]:
        """Get a simulation by ID."""
        return self.simulations.get(simulation_id)
    
    def get_simulations_by_twin(self, twin_id: str) -> List[Simulation]:
        """Get all simulations for a twin."""
        return [s for s in self.simulations.values() if s.twin_id == twin_id]


class ScenarioBuilder:
    """Builder for simulation scenarios."""
    
    def __init__(self):
        self.scenarios: Dict[str, Scenario] = {}
        self._initialize_default_scenarios()
    
    def _initialize_default_scenarios(self):
        """Initialize default scenarios."""
        scenarios = [
            Scenario(
                scenario_id="sc-001",
                name="Fraud Attack Simulation",
                description="Simulate a coordinated fraud attack",
                scenario_type=ScenarioType.ATTACK_SIMULATION,
                twin_type=TwinType.FRAUD_ECOSYSTEM,
                steps=[
                    {"step": 1, "action": "Create mule accounts", "duration": 60},
                    {"step": 2, "action": "Execute test transactions", "duration": 120},
                    {"step": 3, "action": "Scale attack", "duration": 300},
                ],
                expected_outcomes=["Detection alerts", "Risk score increase"],
                success_criteria={"detection_rate": 0.9},
            ),
            Scenario(
                scenario_id="sc-002",
                name="Ransomware Attack Simulation",
                description="Simulate a ransomware attack scenario",
                scenario_type=ScenarioType.ATTACK_SIMULATION,
                twin_type=TwinType.CYBER_NETWORK,
                steps=[
                    {"step": 1, "action": "Initial access", "duration": 30},
                    {"step": 2, "action": "Lateral movement", "duration": 120},
                    {"step": 3, "action": "Data exfiltration", "duration": 60},
                    {"step": 4, "action": "Ransomware deployment", "duration": 30},
                ],
                expected_outcomes=["Alert triggered", "Containment successful"],
                success_criteria={"containment_time": 300},
            ),
        ]
        
        for scenario in scenarios:
            self.scenarios[scenario.scenario_id] = scenario
    
    def create_scenario(
        self,
        name: str,
        description: str,
        scenario_type: ScenarioType,
        twin_type: TwinType,
        steps: List[Dict[str, Any]],
        expected_outcomes: List[str],
        success_criteria: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a new scenario."""
        scenario_id = str(uuid4())
        
        scenario = Scenario(
            scenario_id=scenario_id,
            name=name,
            description=description,
            scenario_type=scenario_type,
            twin_type=twin_type,
            steps=steps,
            expected_outcomes=expected_outcomes,
            success_criteria=success_criteria or {},
        )
        
        self.scenarios[scenario_id] = scenario
        return scenario_id
    
    def get_scenario(self, scenario_id: str) -> Optional[Scenario]:
        """Get a scenario by ID."""
        return self.scenarios.get(scenario_id)
    
    def get_scenarios_by_type(self, scenario_type: ScenarioType) -> List[Scenario]:
        """Get scenarios by type."""
        return [s for s in self.scenarios.values() if s.scenario_type == scenario_type]


class ThreatModelingEngine:
    """Engine for threat modeling."""
    
    def __init__(self):
        self.models: Dict[str, Dict[str, Any]] = {}
    
    def create_threat_model(
        self,
        twin_id: str,
        threat_scenario: Dict[str, Any],
    ) -> str:
        """Create a threat model."""
        model_id = str(uuid4())
        
        self.models[model_id] = {
            "model_id": model_id,
            "twin_id": twin_id,
            "threat_scenario": threat_scenario,
            "attack_paths": self._generate_attack_paths(threat_scenario),
            "vulnerabilities": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        
        return model_id
    
    def _generate_attack_paths(
        self,
        threat_scenario: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate attack paths."""
        paths = []
        
        attack_types = threat_scenario.get("attack_types", ["phishing", "malware", "insider"])
        
        for attack_type in attack_types:
            paths.append({
                "path_id": str(uuid4()),
                "attack_type": attack_type,
                "steps": ["reconnaissance", "initial_access", "execution", "impact"],
                "likelihood": random.uniform(0.3, 0.9),
                "impact": random.uniform(0.5, 1.0),
            })
        
        return paths
    
    def evaluate_risk(
        self,
        twin_id: str,
        threat_model_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate risk based on threat model."""
        return {
            "twin_id": twin_id,
            "risk_score": random.uniform(0.2, 0.8),
            "threat_count": random.randint(5, 20),
            "vulnerability_count": random.randint(2, 10),
            "attack_probability": random.uniform(0.3, 0.7),
        }


class RiskImpactAnalyzer:
    """Analyzer for risk impact."""
    
    def analyze(
        self,
        twin_id: str,
        affected_entities: List[str],
        threat_level: float = 0.5,
    ) -> RiskAnalysis:
        """Analyze risk impact."""
        analysis_id = str(uuid4())
        
        risk_factors = []
        if threat_level > 0.7:
            risk_factors.append({
                "factor": "High Threat Level",
                "impact": 0.3,
                "description": "Threat level exceeds safe threshold",
            })
        
        if len(affected_entities) > 10:
            risk_factors.append({
                "factor": "Widespread Impact",
                "impact": 0.2,
                "description": "Large number of entities affected",
            })
        
        return RiskAnalysis(
            analysis_id=analysis_id,
            twin_id=twin_id,
            risk_score=min(1.0, threat_level + len(affected_entities) * 0.01),
            affected_entities=affected_entities,
            risk_factors=risk_factors,
            mitigation_actions=["Enable monitoring", "Block suspicious activity"],
            recommendations=["Review access controls", "Update security policies"],
        )


class DigitalTwinEngine:
    """Main digital twin engine."""
    
    def __init__(self):
        self.twins: Dict[str, DigitalTwin] = {}
        self.simulation_manager = SimulationManager()
        self.scenario_builder = ScenarioBuilder()
        self.threat_engine = ThreatModelingEngine()
        self.risk_analyzer = RiskImpactAnalyzer()
    
    def create_twin(
        self,
        name: str,
        twin_type: TwinType,
        entities: Optional[List[Dict[str, Any]]] = None,
        relationships: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Create a digital twin."""
        twin_id = str(uuid4())
        
        twin = DigitalTwin(
            twin_id=twin_id,
            name=name,
            twin_type=twin_type,
            entities=entities or [],
            relationships=relationships or [],
            metrics={"entity_count": len(entities) if entities else 0},
        )
        
        self.twins[twin_id] = twin
        return twin_id
    
    def get_twin(self, twin_id: str) -> Optional[DigitalTwin]:
        """Get a twin by ID."""
        return self.twins.get(twin_id)
    
    def update_twin(
        self,
        twin_id: str,
        entities: Optional[List[Dict[str, Any]]] = None,
        relationships: Optional[List[Dict[str, Any]]] = None,
        metrics: Optional[Dict[str, float]] = None,
    ) -> bool:
        """Update a twin."""
        twin = self.twins.get(twin_id)
        if not twin:
            return False
        
        if entities:
            twin.entities = entities
        if relationships:
            twin.relationships = relationships
        if metrics:
            twin.metrics.update(metrics)
        
        twin.updated_at = datetime.now(timezone.utc)
        return True
    
    def simulate(
        self,
        twin_id: str,
        scenario_id: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Run a simulation."""
        twin = self.twins.get(twin_id)
        if not twin:
            raise ValueError(f"Twin {twin_id} not found")
        
        scenario = self.scenario_builder.get_scenario(scenario_id)
        if not scenario:
            raise ValueError(f"Scenario {scenario_id} not found")
        
        simulation_id = self.simulation_manager.create_simulation(
            twin_id=twin_id,
            scenario_type=scenario.scenario_type,
            parameters=parameters,
        )
        
        self.simulation_manager.start_simulation(simulation_id)
        
        results = {
            "scenario_name": scenario.name,
            "steps_completed": len(scenario.steps),
            "duration": sum(s.get("duration", 60) for s in scenario.steps),
            "outcomes": scenario.expected_outcomes,
        }
        
        self.simulation_manager.complete_simulation(simulation_id, results)
        
        return simulation_id
    
    def get_dashboard(self, twin_id: str) -> Dict[str, Any]:
        """Get dashboard for a twin."""
        twin = self.twins.get(twin_id)
        if not twin:
            return {"error": "Twin not found"}
        
        simulations = self.simulation_manager.get_simulations_by_twin(twin_id)
        
        return {
            "twin_id": twin_id,
            "name": twin.name,
            "twin_type": twin.twin_type.value,
            "entity_count": len(twin.entities),
            "relationship_count": len(twin.relationships),
            "simulation_count": len(simulations),
            "completed_simulations": sum(1 for s in simulations if s.status == SimulationStatus.COMPLETED),
            "metrics": twin.metrics,
        }


def get_digital_twin_engine() -> DigitalTwinEngine:
    """Get the global digital twin engine instance."""
    global _digital_twin_engine
    if _digital_twin_engine is None:
        _digital_twin_engine = DigitalTwinEngine()
    return _digital_twin_engine


_digital_twin_engine: Optional[DigitalTwinEngine] = None