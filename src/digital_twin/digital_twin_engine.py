"""
Digital Twin Engine
Enterprise ecosystem simulation and analysis.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

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

    #: Base likelihood that an attack of each type is attempted successfully
    #: against an unhardened target, before scenario modifiers.
    ATTACK_LIKELIHOOD: Dict[str, float] = {
        "phishing": 0.6,
        "credential_stuffing": 0.5,
        "malware": 0.45,
        "ddos": 0.35,
        "insider": 0.25,
        "supply_chain": 0.2,
    }

    #: Base impact of each attack type if it succeeds.
    ATTACK_IMPACT: Dict[str, float] = {
        "supply_chain": 0.9,
        "insider": 0.85,
        "malware": 0.75,
        "credential_stuffing": 0.6,
        "phishing": 0.5,
        "ddos": 0.4,
    }

    #: Applied to attack types with no entry in the tables above.
    DEFAULT_LIKELIHOOD = 0.4
    DEFAULT_IMPACT = 0.6

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
        """Generate attack paths.

        Likelihood and impact come from the attack type and the scenario's own
        parameters. They used to be ``random.uniform`` draws, so the same
        threat model scored differently every time it was built, and a
        supply chain attack could score below a DDoS.
        """
        paths = []

        attack_types = threat_scenario.get("attack_types", ["phishing", "malware", "insider"])

        # Scenario modifiers, all optional and defaulted to neutral.
        sophistication = self._clamp(threat_scenario.get("sophistication", 0.5))
        controls = self._clamp(threat_scenario.get("controls_effectiveness", 0.0))
        criticality = self._clamp(threat_scenario.get("asset_criticality", 0.5))

        for attack_type in attack_types:
            base_likelihood = self.ATTACK_LIKELIHOOD.get(
                str(attack_type).lower(), self.DEFAULT_LIKELIHOOD,
            )
            base_impact = self.ATTACK_IMPACT.get(
                str(attack_type).lower(), self.DEFAULT_IMPACT,
            )

            # A more sophisticated adversary is likelier to get through;
            # effective controls cut that down proportionally.
            likelihood = base_likelihood * (0.5 + sophistication) * (1 - controls)

            # Impact scales with how critical the assets in scope are.
            impact = base_impact * (0.5 + criticality)

            paths.append({
                "path_id": str(uuid4()),
                "attack_type": attack_type,
                "steps": ["reconnaissance", "initial_access", "execution", "impact"],
                "likelihood": round(self._clamp(likelihood), 3),
                "impact": round(self._clamp(impact), 3),
            })

        return paths

    @staticmethod
    def _clamp(value: Any, low: float = 0.0, high: float = 1.0) -> float:
        """Constrain a caller-supplied modifier to [0, 1]."""
        try:
            return max(low, min(high, float(value)))
        except (TypeError, ValueError):
            return low

    def evaluate_risk(
        self,
        twin_id: str,
        threat_model_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate risk based on threat model.

        Both arguments used to be ignored outright: the method returned four
        independent random numbers, so a twin with no threat model at all
        still reported between 5 and 20 threats.
        """
        if threat_model_id is not None:
            model = self.models.get(threat_model_id)
            models = [model] if model else []
        else:
            models = [m for m in self.models.values() if m["twin_id"] == twin_id]

        paths = [path for model in models for path in model["attack_paths"]]

        if not paths:
            return {
                "twin_id": twin_id,
                "risk_score": 0.0,
                "threat_count": 0,
                "vulnerability_count": 0,
                "attack_probability": 0.0,
                "models_evaluated": len(models),
                "insufficient_data": True,
            }

        # Risk is carried by the worst credible path, not the average -- an
        # attacker only needs one to work.
        risk_score = max(p["likelihood"] * p["impact"] for p in paths)

        # Probability that at least one path succeeds, treating paths as
        # independent.
        no_success = 1.0
        for path in paths:
            no_success *= (1 - path["likelihood"])

        return {
            "twin_id": twin_id,
            "risk_score": round(risk_score, 3),
            "threat_count": len(paths),
            "vulnerability_count": sum(len(m["vulnerabilities"]) for m in models),
            "attack_probability": round(1 - no_success, 3),
            "models_evaluated": len(models),
            "insufficient_data": False,
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