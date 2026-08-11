"""
Attack Path Prediction Engine.

Predicts future attack paths and fraud network expansion.
"""

import time
import threading
from threading import Lock
from typing import Dict, List, Optional, Any, Set, Tuple
import logging

from src.graph_analytics.service import GraphService, get_graph_service

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
    
    #: Fallback exposure attributed to a path node that records no transaction
    #: value, so damage stays proportional to path length rather than zero.
    DEFAULT_NODE_EXPOSURE = 5000.0

    #: Edge weight assumed when a real edge records none, so a path is not
    #: discarded merely for lacking a weight.
    DEFAULT_EDGE_WEIGHT = 0.5

    #: Confidence attributed to a prediction that could not leave the source,
    #: because the graph knows of no onward hop.
    NO_PATH_CONFIDENCE = 0.15

    def __init__(
        self,
        store: Optional[PredictiveStore] = None,
        graph: Optional[GraphService] = None,
    ):
        """Initialize the attack path predictor.

        Args:
            store: Optional predictive store
            graph: Optional graph analytics service supplying the real
                neighbourhood an attack could traverse; defaults to the shared
                instance
        """
        self._store = store or get_predictive_store()
        self._graph = graph or get_graph_service()
    
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

        # Each hop is now a real neighbour taken from the graph. This
        # previously appended `hop_<i>_<random int>` identifiers, so every
        # predicted path named entities that existed in no store: an analyst
        # could not look up a single hop, and the path could never be actioned.
        predicted_path, hop_weights = self._extend_path(predicted_path, depth)

        # Probability now compounds the strength of the links actually
        # traversed, rather than depending only on how many hops were invented.
        probability = self._path_probability(predicted_path, hop_weights)

        estimated_damage = self._estimate_damage(predicted_path)

        prediction = AttackPathPrediction(
            source_entity_id=source_entity_id,
            predicted_path=predicted_path,
            probability=probability,
            estimated_damage=estimated_damage,
            confidence=self._path_confidence(known_path, predicted_path, depth),
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
        entity_count = len(current_entities)

        # Growth is bounded by the network's real expansion surface: the
        # entities adjacent to the network that are not yet part of it. The
        # growth multiplier, connection rate, risk escalation and confidence
        # were each a random draw, so a fully isolated network was predicted to
        # grow just as aggressively as a densely connected one.
        frontier, frontier_risks, edge_count = self._expansion_surface(current_entities)

        predicted_new_entities = len(frontier)
        predicted_connections = edge_count

        # Escalation is the risk the frontier would bring in, relative to a
        # maximum of 1.0, scaled by how much the network would grow.
        mean_frontier_risk = (
            sum(frontier_risks) / len(frontier_risks) if frontier_risks else 0.0
        )
        growth_ratio = (
            predicted_new_entities / entity_count if entity_count else 0.0
        )
        risk_escalation = round(min(1.0, mean_frontier_risk * min(growth_ratio, 1.0)), 4)

        return {
            "current_entities": entity_count,
            "predicted_new_entities": predicted_new_entities,
            "predicted_connections": predicted_connections,
            "risk_escalation": risk_escalation,
            "time_horizon": time_horizon,
            "confidence": self._evolution_confidence(entity_count, frontier),
            "new_entity_patterns": self._observed_patterns(frontier),
            "predicted_expansion_patterns": [
                "geo_spread",
                "campaign_integration",
                "mule_network",
            ],
        }

    def _neighbours(self, entity_id: str) -> List[Dict[str, Any]]:
        """Real neighbourhood of an entity, as node dicts.

        Returns an empty list when the graph is unavailable, which callers
        report as an absence of onward path rather than inventing one.
        """
        try:
            network = self._graph.get_entity_network(entity_id, depth=1)
        except Exception as e:
            logger.error(
                "Failed to read neighbourhood of %s: %s", entity_id, e, exc_info=True
            )
            return []

        return [
            node for node in network.get("nodes", [])
            if node.get("node_id") and node.get("node_id") != entity_id
        ]

    def _extend_path(
        self,
        path: List[str],
        depth: int,
    ) -> Tuple[List[str], List[float]]:
        """Walk the graph forward, taking the highest-risk unvisited neighbour.

        An attacker moving laterally heads toward the most valuable or most
        compromised adjacent account, so the highest-risk unvisited neighbour is
        the most probable next hop. Walking stops when the graph offers none,
        which is a real answer: the path ends there.

        Returns:
            Tuple of (path, weight of each hop taken).
        """
        extended = list(path)
        visited = set(extended)
        weights: List[float] = []

        for _ in range(max(0, depth)):
            current = extended[-1]
            candidates = [
                node for node in self._neighbours(current)
                if node.get("node_id") not in visited
            ]

            if not candidates:
                # No onward hop exists. Reporting a shorter path is correct;
                # padding it with invented ids is what this fix removes.
                break

            # Highest risk first, node_id breaking ties so the walk is stable.
            candidates.sort(
                key=lambda n: (-float(n.get("risk_score", 0.0) or 0.0), str(n.get("node_id")))
            )
            chosen = candidates[0]
            node_id = chosen["node_id"]

            extended.append(node_id)
            visited.add(node_id)
            weights.append(self._hop_weight(current, node_id))

        return extended, weights

    def _hop_weight(self, source_id: str, target_id: str) -> float:
        """Strength of the link between two entities."""
        try:
            weight = float(self._graph.get_connection_strength(source_id, target_id) or 0.0)
        except Exception as e:
            logger.error(
                "Failed to measure link %s -> %s: %s", source_id, target_id, e, exc_info=True
            )
            return self.DEFAULT_EDGE_WEIGHT

        if weight <= 0:
            return self.DEFAULT_EDGE_WEIGHT
        return min(1.0, weight)

    def _path_probability(self, path: List[str], hop_weights: List[float]) -> float:
        """Probability the full path is traversed.

        Compounds the strength of each link actually traversed, so a path
        through weak links is less probable than one through strong links of
        the same length. The original computed `0.8 - len(path)/10`, which
        depended only on how many hops had been invented.
        """
        if not hop_weights:
            # A path of one entity is where the attacker already is.
            return 1.0 if len(path) <= 1 else 0.1

        probability = 1.0
        for weight in hop_weights:
            probability *= weight

        return round(max(0.01, min(1.0, probability)), 4)

    def _estimate_damage(self, path: List[str]) -> float:
        """Sum the exposure recorded against entities on the path.

        Previously `len(path) * random.uniform(5000, 25000)`, so the same path
        reported a different loss on each call and the figure could not be
        reconciled against any account.
        """
        total = 0.0

        for entity_id in path:
            exposure = None
            try:
                network = self._graph.get_entity_network(entity_id, depth=0)
                for node in network.get("nodes", []):
                    if node.get("node_id") == entity_id:
                        properties = node.get("properties") or {}
                        exposure = self._coerce_amount(
                            properties.get("total_amount")
                            if properties.get("total_amount") is not None
                            else properties.get("transaction_volume")
                        )
                        break
            except Exception as e:
                logger.error(
                    "Failed to read exposure for %s: %s", entity_id, e, exc_info=True
                )

            total += exposure if exposure is not None else self.DEFAULT_NODE_EXPOSURE

        return round(total, 2)

    def _path_confidence(
        self,
        known_path: List[str],
        predicted_path: List[str],
        depth: int,
    ) -> float:
        """Confidence in the predicted extension.

        Rises with how much of the requested depth the graph could actually
        supply. Confidence was `random.uniform(0.55, 0.80)`, so a prediction
        that found no onward hop at all was reported as confidently as one that
        traced a full path through real links.
        """
        hops_found = len(predicted_path) - len(known_path)

        if hops_found <= 0:
            return self.NO_PATH_CONFIDENCE

        coverage = hops_found / depth if depth else 0.0
        return round(min(0.9, 0.3 + 0.6 * coverage), 2)

    def _expansion_surface(
        self,
        current_entities: Set[str],
    ) -> Tuple[List[str], List[float], int]:
        """Entities adjacent to the network but not yet in it.

        Returns:
            Tuple of (frontier entity ids, their risk scores, count of links
            from the network to that frontier).
        """
        frontier: Dict[str, float] = {}
        edge_count = 0

        for entity_id in current_entities:
            for node in self._neighbours(entity_id):
                node_id = node["node_id"]
                if node_id in current_entities:
                    continue

                edge_count += 1
                if node_id not in frontier:
                    frontier[node_id] = float(node.get("risk_score", 0.0) or 0.0)

        ordered = sorted(frontier)
        return ordered, [frontier[node_id] for node_id in ordered], edge_count

    def _evolution_confidence(self, entity_count: int, frontier: List[str]) -> float:
        """Confidence in an evolution prediction."""
        if not entity_count:
            return self.NO_PATH_CONFIDENCE
        if not frontier:
            # The network is isolated; predicting no growth is well supported.
            return 0.7

        # Saturates at 20 frontier entities.
        support = min(len(frontier), 20) / 20.0
        return round(min(0.9, 0.4 + 0.5 * support), 2)

    def _observed_patterns(self, frontier: List[str]) -> List[str]:
        """Expansion patterns evidenced by the frontier's node types."""
        if not frontier:
            return []

        patterns = set()
        for entity_id in frontier:
            for node in self._neighbours(entity_id):
                node_type = str(node.get("node_type", "")).lower()
                if node_type == "device":
                    patterns.add("device_sharing")
                elif node_type == "ip_address":
                    patterns.add("ip_rotation")
                elif node_type == "account":
                    patterns.add("account_creation")

        return sorted(patterns)

    @staticmethod
    def _coerce_amount(value: Any) -> Optional[float]:
        """Coerce a stored exposure value to a non-negative float."""
        if value is None or isinstance(value, bool):
            return None

        try:
            amount = float(value)
        except (TypeError, ValueError):
            return None

        if amount != amount or amount in (float("inf"), float("-inf")):
            return None

        return abs(amount)
    
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
_attack_path_predictor_lock = Lock()


def get_attack_path_predictor(store: Optional[PredictiveStore] = None) -> AttackPathPredictor:
    """Get or create the singleton AttackPathPredictor instance."""
    global _attack_path_predictor
    
    with _attack_path_predictor_lock:
        if _attack_path_predictor is None:
            _attack_path_predictor = AttackPathPredictor(store=store)
        return _attack_path_predictor