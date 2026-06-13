"""
Threat Simulation Engine
Advanced environment for simulating attacks and threats.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
import random

from .models import (
    ThreatActor,
    AttackType,
    AttackScenario,
    SimulationRun,
    SimulationRunStatus,
    ThreatEvaluation,
    ThreatLevel,
)


class AdversaryModelingEngine:
    """Engine for adversary modeling."""
    
    def __init__(self):
        self.actors: Dict[str, ThreatActor] = {}
        self._initialize_default_actors()
    
    def _initialize_default_actors(self):
        """Initialize default threat actors."""
        actors = [
            ThreatActor(
                actor_id="actor-001",
                name="Nation-State APT",
                sophistication="ADVANCED",
                motivation="Espionage",
                capabilities=["zero-day", "advanced-malware", "social-engineering"],
                targets=["financial", "government", "infrastructure"],
            ),
            ThreatActor(
                actor_id="actor-002",
                name="Cybercriminal Group",
                sophistication="INTERMEDIATE",
                motivation="Financial Gain",
                capabilities=["ransomware", "phishing", "fraud"],
                targets=["financial", "retail", "healthcare"],
            ),
            ThreatActor(
                actor_id="actor-003",
                name="Insider Threat",
                sophistication="LOW",
                motivation="Revenge or Profit",
                capabilities=["access-abuse", "data-theft"],
                targets=["internal-systems", "data"],
            ),
        ]
        
        for actor in actors:
            self.actors[actor.actor_id] = actor
    
    def create_actor(
        self,
        name: str,
        sophistication: str,
        motivation: str,
        capabilities: List[str],
        targets: List[str],
    ) -> str:
        """Create a new threat actor."""
        actor_id = str(uuid4())
        
        actor = ThreatActor(
            actor_id=actor_id,
            name=name,
            sophistication=sophistication,
            motivation=motivation,
            capabilities=capabilities,
            targets=targets,
        )
        
        self.actors[actor_id] = actor
        return actor_id
    
    def get_actor(self, actor_id: str) -> Optional[ThreatActor]:
        """Get a threat actor by ID."""
        return self.actors.get(actor_id)
    
    def get_actors_by_target(self, target: str) -> List[ThreatActor]:
        """Get actors targeting a specific sector."""
        return [a for a in self.actors.values() if target in a.targets]


class ScenarioBuilder:
    """Builder for attack scenarios."""
    
    def __init__(self):
        self.scenarios: Dict[str, AttackScenario] = {}
        self._initialize_default_scenarios()
    
    def _initialize_default_scenarios(self):
        """Initialize default scenarios."""
        scenarios = [
            AttackScenario(
                scenario_id="asc-001",
                name="Phishing Campaign",
                attack_type=AttackType.PHISHING,
                description="Simulate a phishing campaign attack",
                steps=[
                    {"step": 1, "action": "Reconnaissance", "duration": 30},
                    {"step": 2, "action": "Email crafting", "duration": 60},
                    {"step": 3, "action": "Delivery", "duration": 10},
                    {"step": 4, "action": "Credential harvesting", "duration": 120},
                ],
                prerequisites=["email-list", "phishing-template"],
                expected_impact={"success-rate": 0.3, "impact-level": "MEDIUM"},
                success_indicators=["credential-captured", "lateral-movement"],
            ),
            AttackScenario(
                scenario_id="asc-002",
                name="Ransomware Attack",
                attack_type=AttackType.RANSOMWARE,
                description="Simulate a ransomware attack",
                steps=[
                    {"step": 1, "action": "Initial access", "duration": 60},
                    {"step": 2, "action": "Lateral movement", "duration": 180},
                    {"step": 3, "action": "Data encryption", "duration": 120},
                    {"step": 4, "action": "Ransom demand", "duration": 30},
                ],
                prerequisites=["network-access", "malware-build"],
                expected_impact={"success-rate": 0.6, "impact-level": "CRITICAL"},
                success_indicators=["systems-encrypted", "ransom-delivered"],
            ),
            AttackScenario(
                scenario_id="asc-003",
                name="Fraud Attack Simulation",
                attack_type=AttackType.FRAUD_ATTACK,
                description="Simulate coordinated fraud attack",
                steps=[
                    {"step": 1, "action": "Mule account creation", "duration": 60},
                    {"step": 2, "action": "Test transactions", "duration": 30},
                    {"step": 3, "action": "Scale attack", "duration": 300},
                    {"step": 4, "action": "Money laundering", "duration": 120},
                ],
                prerequisites=["synthetic-accounts", "money-mules"],
                expected_impact={"success-rate": 0.4, "impact-level": "HIGH"},
                success_indicators=["transactions-processed", "funds-laundered"],
            ),
        ]
        
        for scenario in scenarios:
            self.scenarios[scenario.scenario_id] = scenario
    
    def create_scenario(
        self,
        name: str,
        attack_type: AttackType,
        description: str,
        steps: List[Dict[str, Any]],
        prerequisites: Optional[List[str]] = None,
        expected_impact: Optional[Dict[str, Any]] = None,
        success_indicators: Optional[List[str]] = None,
    ) -> str:
        """Create a new attack scenario."""
        scenario_id = str(uuid4())
        
        scenario = AttackScenario(
            scenario_id=scenario_id,
            name=name,
            attack_type=attack_type,
            description=description,
            steps=steps,
            prerequisites=prerequisites or [],
            expected_impact=expected_impact or {},
            success_indicators=success_indicators or [],
        )
        
        self.scenarios[scenario_id] = scenario
        return scenario_id
    
    def get_scenario(self, scenario_id: str) -> Optional[AttackScenario]:
        """Get a scenario by ID."""
        return self.scenarios.get(scenario_id)


class ThreatSimulator:
    """Main threat simulator."""
    
    def __init__(self):
        self.runs: Dict[str, SimulationRun] = {}
        self.adversary_engine = AdversaryModelingEngine()
        self.scenario_builder = ScenarioBuilder()
    
    def start_simulation(
        self,
        scenario_id: str,
        actor_id: str,
    ) -> str:
        """Start a simulation run."""
        scenario = self.scenario_builder.get_scenario(scenario_id)
        if not scenario:
            raise ValueError(f"Scenario {scenario_id} not found")
        
        actor = self.adversary_engine.get_actor(actor_id)
        if not actor:
            raise ValueError(f"Actor {actor_id} not found")
        
        run_id = str(uuid4())
        
        run = SimulationRun(
            run_id=run_id,
            scenario_id=scenario_id,
            actor_id=actor_id,
            status=SimulationRunStatus.RUNNING,
            start_time=datetime.now(timezone.utc),
        )
        
        self.runs[run_id] = run
        return run_id
    
    def execute_step(
        self,
        run_id: str,
        step: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute a simulation step."""
        run = self.runs.get(run_id)
        if not run:
            return {"error": "Run not found"}
        
        event = {
            "step": step.get("step"),
            "action": step.get("action"),
            "duration": step.get("duration", 0),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "outcome": random.choice(["success", "partial", "blocked"]),
        }
        
        run.events.append(event)
        return event
    
    def complete_simulation(
        self,
        run_id: str,
        results: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Complete a simulation run."""
        run = self.runs.get(run_id)
        if not run:
            return False
        
        run.status = SimulationRunStatus.COMPLETED
        run.end_time = datetime.now(timezone.utc)
        
        if results:
            run.results = results
        
        run.metrics = {
            "total_steps": len(run.events),
            "successful_steps": sum(1 for e in run.events if e.get("outcome") == "success"),
            "duration": (run.end_time - run.start_time).total_seconds() if run.start_time else 0,
        }
        
        return True
    
    def get_run(self, run_id: str) -> Optional[SimulationRun]:
        """Get a simulation run by ID."""
        return self.runs.get(run_id)
    
    def get_runs_by_scenario(self, scenario_id: str) -> List[SimulationRun]:
        """Get all runs for a scenario."""
        return [r for r in self.runs.values() if r.scenario_id == scenario_id]
    
    def evaluate_threat(self, run_id: str) -> ThreatEvaluation:
        """Evaluate threat from simulation run."""
        run = self.runs.get(run_id)
        if not run:
            raise ValueError(f"Run {run_id} not found")
        
        successful = sum(1 for e in run.events if e.get("outcome") == "success")
        total = len(run.events)
        
        threat_score = successful / max(1, total) if total > 0 else 0
        detection_rate = random.uniform(0.5, 0.95)
        response_time = random.uniform(30, 300)
        
        return ThreatEvaluation(
            evaluation_id=str(uuid4()),
            run_id=run_id,
            threat_score=threat_score,
            detection_rate=detection_rate,
            response_time=response_time,
            effectiveness=detection_rate * (1 - threat_score),
            recommendations=[
                "Improve detection mechanisms",
                "Enhance response procedures",
                "Update security controls",
            ],
        )


class SimulationAnalytics:
    """Analytics for simulation results."""
    
    def __init__(self, simulator: Optional[ThreatSimulator] = None):
        self.simulator = simulator or ThreatSimulator()
        self.evaluations: Dict[str, ThreatEvaluation] = {}
    
    def run_analytics(
        self,
        run_id: str,
    ) -> Dict[str, Any]:
        """Run analytics on a simulation."""
        evaluation = self.simulator.evaluate_threat(run_id)
        self.evaluations[evaluation.evaluation_id] = evaluation
        
        return {
            "evaluation_id": evaluation.evaluation_id,
            "threat_score": evaluation.threat_score,
            "detection_rate": evaluation.detection_rate,
            "effectiveness": evaluation.effectiveness,
            "recommendations": evaluation.recommendations,
        }
    
    def get_summary_report(self) -> Dict[str, Any]:
        """Get summary report of all evaluations."""
        if not self.evaluations:
            return {"total_evaluations": 0}
        
        avg_threat = sum(e.threat_score for e in self.evaluations.values()) / len(self.evaluations)
        avg_detection = sum(e.detection_rate for e in self.evaluations.values()) / len(self.evaluations)
        
        return {
            "total_evaluations": len(self.evaluations),
            "average_threat_score": avg_threat,
            "average_detection_rate": avg_detection,
            "effectiveness_score": avg_detection * (1 - avg_threat),
        }


def get_threat_simulator() -> ThreatSimulator:
    """Get the global threat simulator instance."""
    global _threat_simulator
    if _threat_simulator is None:
        _threat_simulator = ThreatSimulator()
    return _threat_simulator


_threat_simulator: Optional[ThreatSimulator] = None