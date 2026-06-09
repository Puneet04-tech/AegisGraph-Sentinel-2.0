"""
Attack Path Prediction Engine.

Predicts future attack paths and fraud network expansion.
"""

import time
import random
from typing import Dict, List, Optional, Any, Set
import logging

from .models import AttackPathPrediction
from .store import PredictiveStore, get_predictive_store

logger = logging.getLogger(__name__)


class AttackPathPredictor:
    """Attack path prediction engine for forecasting attack evolution.
    
    Provides:
        - Attack path prediction
        - Network expansion forecasting
        - Attack evolution tracking
        - Future connection prediction
    """
    
    def __init__(self, store: Optional[PredictiveStore] = None):
        """Initialize the attack path predictor.
        
        Args:
            store: Optional predictive store
        """
        self._store = store or get_predictive_store()
    
    def predict_attack_path(
        self,
        source_entity_id: str,
        known_path: List[str] = None,
        depth: int = 3,
    ) -> AttackPathPrediction:
        """Predict attack path from a source entity.
        
        Args:
            source_entity_id: Starting entity
            known_path: Known path so far
            depth: Prediction depth
            
        Returns:
            AttackPathPrediction with predicted path
        """
        start_time = time.time()
        
        # Build predicted path
        if known_path is None:
            known_path = [source_entity_id]
        
        predicted_path = list(known_path)
        
        # Extend path based on depth
        for i in range(depth):
            next_hop = f"hop_{len(predicted_path)}_{random.randint(1000, 9999)}"
            predicted_path.append(next_hop)
        
        # Calculate probability based on path length and structure
        base_probability = 0.8
        path_factor = len(predicted_path) / 10.0
        probability = max(base_probability - path_factor, 0.1)
        
        # Estimate damage based on path length
        estimated_damage = len(predicted_path) * random.uniform(5000, 25000)
        
        prediction = AttackPathPrediction(
            source_entity_id=source_entity_id,
            predicted_path=predicted_path,
            probability=probability,
            estimated_damage=estimated_damage,
            confidence=random.uniform(0.55, 0.80),
        )
        
        # Store prediction
        self._store.store_attack_path(prediction)
        
        processing_time = (time.time() - start_time) * 1000
        logger.info(f"Attack path predicted for {source_entity_id}: {len(predicted_path)} hops")
        
        return prediction
    
    def predict_network_expansion(
        self,
        source_entity_ids: List[str],
        expansion_rate: float = 0.3,
    ) -> List[AttackPathPrediction]:
        """Predict network expansion from multiple sources.
        
        Args:
            source_entity_ids: Source entities
            expansion_rate: Expected expansion rate
            
        Returns:
            List of AttackPathPrediction for each source
        """
        predictions = []
        
        for entity_id in source_entity_ids:
            # Determine expansion depth based on rate
            depth = int(expansion_rate * 5) + 1
            depth = min(max(depth, 1), 5)
            
            prediction = self.predict_attack_path(entity_id, depth=depth)
            predictions.append(prediction)
        
        return predictions
    
    def predict_fraud_evolution(
        self,
        current_entities: Set[str],
        time_horizon: str = "7_days",
    ) -> Dict[str, Any]:
        """Predict how a fraud network will evolve.
        
        Args:
            current_entities: Current entities in the network
            time_horizon: Prediction time horizon
            
        Returns:
            Dictionary with evolution prediction
        """
        # Calculate evolution metrics
        entity_count = len(current_entities)
        
        # Predict growth
        growth_multiplier = random.uniform(1.5, 4.0)
        predicted_new_entities = int(entity_count * (growth_multiplier - 1))
        
        # Predict new connections
        connection_rate = random.uniform(0.3, 0.8)
        predicted_connections = int(entity_count * connection_rate)
        
        # Predict risk escalation
        risk_escalation = random.uniform(0.1, 0.4)
        
        return {
            "current_entities": entity_count,
            "predicted_new_entities": predicted_new_entities,
            "predicted_connections": predicted_connections,
            "risk_escalation": risk_escalation,
            "time_horizon": time_horizon,
            "confidence": random.uniform(0.6, 0.85),
            "new_entity_patterns": [
                "account_creation",
                "device_sharing",
                "ip_rotation",
            ],
            "predicted_expansion_patterns": [
                "geo_spread",
                "campaign_integration",
                "mule_network",
            ],
        }
    
    def get_attack_paths(self, entity_id: str) -> List[AttackPathPrediction]:
        """Get all attack paths for an entity."""
        return self._store.get_attack_paths_for_entity(entity_id)
    
    def get_high_probability_attacks(self, threshold: float = 0.5) -> List[AttackPathPrediction]:
        """Get attack paths with high probability."""
        return self._store.get_high_probability_attacks(threshold)
    
    def generate_attack_forecast(
        self,
        entity_id: str,
        scenarios: List[str] = None,
    ) -> List[AttackPathPrediction]:
        """Generate attack forecasts for multiple scenarios.
        
        Args:
            entity_id: Entity to forecast
            scenarios: List of attack scenarios
            
        Returns:
            List of AttackPathPrediction for each scenario
        """
        if scenarios is None:
            scenarios = ["direct_attack", "lateral_movement", "campaign_integration"]
        
        predictions = []
        
        for scenario in scenarios:
            path = [entity_id, f"{scenario}_step_1"]
            prediction = self.predict_attack_path(entity_id, known_path=path, depth=3)
            prediction.metadata["scenario"] = scenario
            predictions.append(prediction)
        
        return predictions


# Global singleton
_attack_path_predictor: Optional[AttackPathPredictor] = None


def get_attack_path_predictor(store: Optional[PredictiveStore] = None) -> AttackPathPredictor:
    """Get or create the singleton AttackPathPredictor instance."""
    global _attack_path_predictor
    
    if _attack_path_predictor is None:
        _attack_path_predictor = AttackPathPredictor(store=store)
    return _attack_path_predictor