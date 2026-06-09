"""
Fraud Simulation Engine.

Simulates various fraud scenarios to predict outcomes and risk.
"""

import time
import random
from typing import Dict, List, Optional, Any
import logging

from .models import (
    SimulationScenario,
    SimulationType,
    SimulationStatus,
    SimulationResult,
)
from .store import PredictiveStore, get_predictive_store

logger = logging.getLogger(__name__)


class FraudSimulator:
    """Fraud simulation engine for predicting fraud outcomes.
    
    Simulates:
        - Account takeover attacks
        - Fraud ring expansion
        - Synthetic identity fraud
        - Wallet laundering chains
        - Campaign spread
        - Mule account creation
        - Network infiltration
    """
    
    def __init__(self, store: Optional[PredictiveStore] = None):
        """Initialize the fraud simulator.
        
        Args:
            store: Optional predictive store
        """
        self._store = store or get_predictive_store()
    
    def simulate(self, scenario: SimulationScenario) -> SimulationResult:
        """Run a fraud simulation.
        
        Args:
            scenario: Simulation scenario to run
            
        Returns:
            SimulationResult with predicted outcomes
        """
        start_time = time.time()
        
        # Update scenario status
        scenario.status = SimulationStatus.RUNNING
        self._store.store_scenario(scenario)
        
        try:
            # Route to appropriate simulation method
            if scenario.simulation_type == SimulationType.ACCOUNT_TAKEOVER:
                result = self._simulate_account_takeover(scenario)
            elif scenario.simulation_type == SimulationType.FRAUD_RING_EXPANSION:
                result = self._simulate_fraud_ring_expansion(scenario)
            elif scenario.simulation_type == SimulationType.SYNTHETIC_IDENTITY:
                result = self._simulate_synthetic_identity(scenario)
            elif scenario.simulation_type == SimulationType.WALLET_LAUNDERING:
                result = self._simulate_wallet_laundering(scenario)
            elif scenario.simulation_type == SimulationType.CAMPAIGN_SPREAD:
                result = self._simulate_campaign_spread(scenario)
            elif scenario.simulation_type == SimulationType.MULE_ACCOUNT_CREATION:
                result = self._simulate_mule_account_creation(scenario)
            elif scenario.simulation_type == SimulationType.NETWORK_INFILTRATION:
                result = self._simulate_network_infiltration(scenario)
            else:
                result = self._generic_simulation(scenario)
            
            # Update timing
            result.processing_time_ms = (time.time() - start_time) * 1000
            
            # Store result
            self._store.store_simulation_result(result)
            
            # Update scenario status
            scenario.status = SimulationStatus.COMPLETED
            self._store.store_scenario(scenario)
            
            logger.info(f"Simulation {scenario.scenario_id} completed in {result.processing_time_ms:.2f}ms")
            return result
            
        except Exception as e:
            logger.error(f"Simulation {scenario.scenario_id} failed: {e}")
            scenario.status = SimulationStatus.FAILED
            self._store.store_scenario(scenario)
            raise
    
    def _simulate_account_takeover(self, scenario: SimulationScenario) -> SimulationResult:
        """Simulate account takeover attack."""
        source_count = len(scenario.source_entity_ids)
        base_risk = scenario.parameters.get("base_risk", 0.5)
        compromised_rate = scenario.parameters.get("compromised_rate", 0.3)
        
        # Calculate affected entities
        affected = int(source_count * compromised_rate * random.uniform(1.5, 3.0))
        affected_entities = random.sample(
            scenario.source_entity_ids * 3,
            min(affected, len(scenario.source_entity_ids) * 3)
        )
        
        # Calculate risk score
        risk_score = min(base_risk * (1 + compromised_rate * 0.5), 1.0)
        
        # Generate outcomes
        outcomes = [
            {
                "type": "credential_compromised",
                "probability": compromised_rate,
                "impact": "HIGH",
                "affected_entities": affected,
            },
            {
                "type": "unauthorized_transactions",
                "probability": compromised_rate * 0.7,
                "impact": "CRITICAL",
                "estimated_loss": affected * random.uniform(1000, 10000),
            },
            {
                "type": "lateral_movement",
                "probability": compromised_rate * 0.4,
                "impact": "MEDIUM",
                "spread_risk": 0.3,
            },
        ]
        
        return SimulationResult(
            scenario_id=scenario.scenario_id,
            predicted_outcomes=outcomes,
            risk_score=risk_score,
            affected_entities=affected_entities[:min(len(affected_entities), 100)],
            confidence=0.75,
        )
    
    def _simulate_fraud_ring_expansion(self, scenario: SimulationScenario) -> SimulationResult:
        """Simulate fraud ring expansion."""
        source_count = len(scenario.source_entity_ids)
        expansion_rate = scenario.parameters.get("expansion_rate", 0.2)
        ring_size = scenario.parameters.get("ring_size", 5)
        
        # Calculate expansion
        new_members = int(ring_size * expansion_rate * random.uniform(1.5, 4.0))
        affected_entities = [f"ring_member_{i}" for i in range(new_members)]
        
        # Calculate risk
        risk_score = min(0.6 + (expansion_rate * 0.3), 1.0)
        
        outcomes = [
            {
                "type": "ring_expansion",
                "new_members": new_members,
                "probability": expansion_rate,
                "impact": "HIGH",
            },
            {
                "type": "coordinated_activity",
                "probability": 0.8,
                "impact": "CRITICAL",
                "coordination_score": random.uniform(0.7, 0.95),
            },
            {
                "type": "resource_sharing",
                "probability": 0.6,
                "impact": "MEDIUM",
            },
        ]
        
        return SimulationResult(
            scenario_id=scenario.scenario_id,
            predicted_outcomes=outcomes,
            risk_score=risk_score,
            affected_entities=affected_entities,
            confidence=0.70,
        )
    
    def _simulate_synthetic_identity(self, scenario: SimulationScenario) -> SimulationResult:
        """Simulate synthetic identity fraud."""
        count = len(scenario.source_entity_ids)
        synthetic_rate = scenario.parameters.get("synthetic_rate", 0.15)
        
        affected = int(count * synthetic_rate * random.uniform(2.0, 5.0))
        affected_entities = [f"synthetic_{i}" for i in range(affected)]
        
        risk_score = min(0.5 + (synthetic_rate * 0.4), 1.0)
        
        outcomes = [
            {
                "type": "fake_identities_created",
                "count": affected,
                "probability": synthetic_rate,
                "impact": "HIGH",
            },
            {
                "type": "account_opening",
                "probability": synthetic_rate * 0.8,
                "impact": "CRITICAL",
            },
            {
                "type": "credit_fraud",
                "probability": synthetic_rate * 0.5,
                "impact": "HIGH",
                "estimated_loss": affected * random.uniform(5000, 50000),
            },
        ]
        
        return SimulationResult(
            scenario_id=scenario.scenario_id,
            predicted_outcomes=outcomes,
            risk_score=risk_score,
            affected_entities=affected_entities,
            confidence=0.65,
        )
    
    def _simulate_wallet_laundering(self, scenario: SimulationScenario) -> SimulationResult:
        """Simulate wallet laundering chain."""
        hop_count = scenario.parameters.get("hop_count", 4)
        volume = scenario.parameters.get("volume", 100000)
        
        affected_entities = [f"wallet_{i}" for i in range(hop_count)]
        
        risk_score = min(0.7 + (hop_count * 0.05), 1.0)
        
        outcomes = [
            {
                "type": "funds_mixed",
                "volume": volume * random.uniform(0.8, 1.2),
                "probability": 0.85,
                "impact": "CRITICAL",
            },
            {
                "type": "chain_length",
                "hops": hop_count,
                "obfuscation_score": random.uniform(0.6, 0.9),
                "impact": "HIGH",
            },
            {
                "type": "cash_out",
                "probability": 0.7,
                "impact": "HIGH",
                "exit_risk": random.uniform(0.5, 0.8),
            },
        ]
        
        return SimulationResult(
            scenario_id=scenario.scenario_id,
            predicted_outcomes=outcomes,
            risk_score=risk_score,
            affected_entities=affected_entities,
            confidence=0.80,
        )
    
    def _simulate_campaign_spread(self, scenario: SimulationScenario) -> SimulationResult:
        """Simulate campaign spread."""
        source_count = len(scenario.source_entity_ids)
        spread_rate = scenario.parameters.get("spread_rate", 0.25)
        
        new_targets = int(source_count * spread_rate * random.uniform(2.0, 6.0))
        affected_entities = [f"target_{i}" for i in range(new_targets)]
        
        risk_score = min(0.5 + (spread_rate * 0.4), 1.0)
        
        outcomes = [
            {
                "type": "campaign_expansion",
                "new_targets": new_targets,
                "spread_rate": spread_rate,
                "probability": 0.75,
                "impact": "HIGH",
            },
            {
                "type": "geo_spread",
                "probability": spread_rate * 0.5,
                "impact": "MEDIUM",
            },
            {
                "type": "campaign_peak",
                "estimated_days": random.randint(5, 30),
                "probability": 0.6,
                "impact": "HIGH",
            },
        ]
        
        return SimulationResult(
            scenario_id=scenario.scenario_id,
            predicted_outcomes=outcomes,
            risk_score=risk_score,
            affected_entities=affected_entities,
            confidence=0.72,
        )
    
    def _simulate_mule_account_creation(self, scenario: SimulationScenario) -> SimulationResult:
        """Simulate mule account creation."""
        count = len(scenario.source_entity_ids)
        creation_rate = scenario.parameters.get("creation_rate", 0.2)
        
        new_mules = int(count * creation_rate * random.uniform(1.5, 4.0))
        affected_entities = [f"mule_{i}" for i in range(new_mules)]
        
        risk_score = min(0.55 + (creation_rate * 0.35), 1.0)
        
        outcomes = [
            {
                "type": "mule_accounts_created",
                "count": new_mules,
                "probability": creation_rate,
                "impact": "CRITICAL",
            },
            {
                "type": "transaction_volume",
                "estimated_volume": new_mules * random.uniform(50000, 500000),
                "probability": 0.8,
                "impact": "HIGH",
            },
            {
                "type": "campaign_integration",
                "probability": 0.65,
                "impact": "HIGH",
            },
        ]
        
        return SimulationResult(
            scenario_id=scenario.scenario_id,
            predicted_outcomes=outcomes,
            risk_score=risk_score,
            affected_entities=affected_entities,
            confidence=0.68,
        )
    
    def _simulate_network_infiltration(self, scenario: SimulationScenario) -> SimulationResult:
        """Simulate network infiltration."""
        entry_points = len(scenario.source_entity_ids)
        infiltration_depth = scenario.parameters.get("infiltration_depth", 3)
        
        compromised = int(entry_points * random.uniform(1.5, 3.0) * infiltration_depth)
        affected_entities = [f"node_{i}" for i in range(compromised)]
        
        risk_score = min(0.65 + (infiltration_depth * 0.1), 1.0)
        
        outcomes = [
            {
                "type": "lateral_movement",
                "depth": infiltration_depth,
                "nodes_compromised": compromised,
                "probability": 0.75,
                "impact": "CRITICAL",
            },
            {
                "type": "privilege_escalation",
                "probability": 0.5,
                "impact": "CRITICAL",
            },
            {
                "type": "data_exfiltration",
                "probability": 0.3,
                "impact": "HIGH",
            },
        ]
        
        return SimulationResult(
            scenario_id=scenario.scenario_id,
            predicted_outcomes=outcomes,
            risk_score=risk_score,
            affected_entities=affected_entities,
            confidence=0.73,
        )
    
    def _generic_simulation(self, scenario: SimulationScenario) -> SimulationResult:
        """Generic simulation for unknown types."""
        risk_score = 0.5
        outcomes = [
            {
                "type": "generic_risk",
                "probability": 0.5,
                "impact": "MEDIUM",
            },
        ]
        
        return SimulationResult(
            scenario_id=scenario.scenario_id,
            predicted_outcomes=outcomes,
            risk_score=risk_score,
            affected_entities=[],
            confidence=0.5,
        )
    
    def get_simulation_result(self, scenario_id: str) -> Optional[SimulationResult]:
        """Get the result of a simulation."""
        return self._store.get_simulation_result(scenario_id)
    
    def get_all_scenarios(self) -> List[SimulationScenario]:
        """Get all simulation scenarios."""
        return self._store.get_all_scenarios()


# Global singleton
_fraud_simulator: Optional[FraudSimulator] = None


def get_fraud_simulator(store: Optional[PredictiveStore] = None) -> FraudSimulator:
    """Get or create the singleton FraudSimulator instance."""
    global _fraud_simulator
    
    if _fraud_simulator is None:
        _fraud_simulator = FraudSimulator(store=store)
    return _fraud_simulator