"""
Risk Scoring Pipeline

Combines multiple fraud signals into a comprehensive risk score:
1. Graph-based risk (HTGNN)
2. Velocity-based risk
3. Behavioral biometrics risk  
4. Entropy-based risk

Thresholds loaded from config/thresholds.yaml - see that file for all
detection limits and sensitivity values.
"""
# Updated: May 17, 2026

import logging
logger = logging.getLogger(__name__)
import torch
import numpy as np
import weakref
from typing import Dict, Optional, Tuple, List
import networkx as nx  #models

from ..models.risk_model import FraudDetectionModel
from ..features.velocity_calculator import VelocityCalculator, Transaction
from ..features.behavioral_biometrics import analyze_keystroke_data
from ..features.entropy_calculator import compute_entropy_risk_score
from ..utils.helpers import get_device, load_thresholds
from ..scoring import ThresholdConfig, RiskScorer as CentralRiskScorer
from ..observability import get_logger
from ..config import defaults as config_defaults

_inference_logger = get_logger("inference.risk_scorer")
_CENTRALITY_CACHE = weakref.WeakKeyDictionary()


def _get_betweenness_centrality(graph: nx.Graph) -> Dict:
    """Cache betweenness centrality per graph instance and topology snapshot."""
    if graph is None:
        return {}

    try:
        signature = (
            graph.number_of_nodes() if hasattr(graph, "number_of_nodes") else 0,
            graph.number_of_edges() if hasattr(graph, "number_of_edges") else 0,
        )
        cached = _CENTRALITY_CACHE.get(graph)
        if cached and cached[0] == signature:
            return cached[1]

        centrality = nx.betweenness_centrality(graph, k=min(100, signature[0] or 1))
        _CENTRALITY_CACHE[graph] = (signature, centrality)
        return centrality
    except TypeError:
        return nx.betweenness_centrality(graph, k=min(100, graph.number_of_nodes()))


class RiskScorer:
    """
    Unified risk scoring system
    
    Combines multiple fraud detection signals with configurable weights
    
    Args:
        model: Trained HTGNN model
        config: Configuration dictionary
        device: torch device
    """
    
    def __init__(
        self,
        model: FraudDetectionModel,
        config: dict,
        device: torch.device = None,
    ):
        self.model = model
        self.config = config
        configured_device = config.get('model', {}).get('device')
        self.device = get_device(str(device) if device is not None else configured_device)
        
        self.model.to(self.device)
        self.model.eval()
        
        # Risk scoring weights
        weights = config.get('risk_scoring', {}).get('weights', {})
        self.w_graph = weights.get('graph', 0.50)
        self.w_velocity = weights.get('velocity', 0.20)
        self.w_behavior = weights.get('behavior', 0.20)
        self.w_entropy = weights.get('entropy', 0.10)
        
        # Thresholds - load from thresholds.yaml with fallback to config.yaml
        try:
            threshold_config = load_thresholds('config/thresholds.yaml', validate=True)
            rs = threshold_config.get('risk_scoring', {})
            self.threshold_block = rs.get('block', config_defaults.DEFAULT_RISK_THRESHOLDS["block"])
            self.threshold_review = rs.get('review', config_defaults.DEFAULT_RISK_THRESHOLDS["review"])
            self.threshold_allow = rs.get('allow', config_defaults.DEFAULT_RISK_THRESHOLDS["allow"])
            
            # Graph analysis thresholds
            ga = threshold_config.get('graph_analysis', {})
            self.lateral_movement_std = ga.get(
                'lateral_movement_std_multiplier',
                config_defaults.DEFAULT_LATERAL_MOVEMENT_STD_MULTIPLIER,
            )
            self.lateral_movement_mult = ga.get(
                'lateral_movement_threshold_multiplier',
                config_defaults.DEFAULT_LATERAL_MOVEMENT_THRESHOLD_MULTIPLIER,
            )
            self.lateral_movement_risk_increment = (
                config_defaults.DEFAULT_LATERAL_MOVEMENT_RISK_INCREMENT
            )
        except Exception as e:
            logger.error(f"Error: {e}")
            # Fallback to config.yaml
            thresholds = config.get('risk_scoring', {}).get('thresholds', {})
            self.threshold_block = thresholds.get('block', config_defaults.DEFAULT_RISK_THRESHOLDS["block"])
            self.threshold_review = thresholds.get('review', config_defaults.DEFAULT_RISK_THRESHOLDS["review"])
            self.threshold_allow = thresholds.get('allow', config_defaults.DEFAULT_RISK_THRESHOLDS["allow"])
            self.lateral_movement_std = config_defaults.DEFAULT_LATERAL_MOVEMENT_STD_MULTIPLIER
            self.lateral_movement_mult = config_defaults.DEFAULT_LATERAL_MOVEMENT_THRESHOLD_MULTIPLIER
            self.lateral_movement_risk_increment = config_defaults.DEFAULT_LATERAL_MOVEMENT_RISK_INCREMENT
        
        thresholds = {
            'allow': self.threshold_allow,
            'review': self.threshold_review,
            'block': self.threshold_block,
        }
        self.threshold_config = ThresholdConfig(thresholds=thresholds)
        self.component_weights = {
            'graph': self.w_graph,
            'velocity': self.w_velocity,
            'behavior': self.w_behavior,
            'entropy': self.w_entropy,
        }
        self.central_scorer = CentralRiskScorer(
            threshold_config=self.threshold_config,
            component_weights=self.component_weights,
        )

        # Feature calculators
        self.velocity_calculator = VelocityCalculator()
    
    @torch.no_grad()
    def compute_risk_score(
        self,
        transaction_data: dict,
        graph_data: Optional[dict] = None,
        behavioral_data: Optional[dict] = None,
        historical_transactions: Optional[List[Transaction]] = None,
        graph: Optional[nx.Graph] = None,
    ) -> Dict[str, float]:
        """
        Compute comprehensive risk score for a transaction
        
        Args:
            transaction_data: Transaction information
            graph_data: Graph representation (node features, edges, etc.)
            behavioral_data: Keystroke/behavioral biometrics
            historical_transactions: Historical transaction sequence
            graph: NetworkX graph for entropy calculation
        
        Returns:
            Dictionary with risk scores and decision
        """
        risk_components = {}
        
        # 1. Graph-based risk (HTGNN)
        if graph_data is not None:
            graph_risk = self._compute_graph_risk(graph_data)
            risk_components['graph'] = graph_risk
        else:
            risk_components['graph'] = 0.5  # Neutral risk
        
        # 2. Velocity-based risk
        if historical_transactions is not None:
            velocity_risk = self._compute_velocity_risk(
                historical_transactions,
                transaction_data.get('timestamp', 0.0),
                graph,
            )
            risk_components['velocity'] = velocity_risk
        else:
            risk_components['velocity'] = 0.5
        
        # 3. Behavioral biometrics risk
        if behavioral_data is not None:
            behavior_risk = self._compute_behavior_risk(behavioral_data)
            risk_components['behavior'] = behavior_risk
        else:
            risk_components['behavior'] = 0.5
        
        # 4. Entropy-based risk
        if graph is not None and graph_data is not None:
            entropy_risk = self._compute_entropy_risk(
                transaction_data.get('source_account', ''),
                graph,
                graph_data,
            )
            risk_components['entropy'] = entropy_risk
        else:
            risk_components['entropy'] = 0.5
        
        component_scores = {
            'graph': risk_components['graph'],
            'velocity': risk_components['velocity'],
            'behavior': risk_components['behavior'],
            'entropy': risk_components['entropy'],
        }
        assessment = self.central_scorer.assess(component_scores)

        return {
            'risk_score': float(assessment.overall_score),
            'decision': assessment.decision,
            'confidence': float(assessment.confidence),
            'breakdown': {k: float(v) for k, v in risk_components.items()},
        }
    
    def _compute_graph_risk(self, graph_data: dict) -> float:
        """Compute risk using HTGNN model"""
        # Move data to device
        x = torch.tensor(graph_data['x'], dtype=torch.float32).to(self.device)
        edge_index = torch.tensor(graph_data['edge_index'], dtype=torch.long).to(self.device)
        node_type = torch.tensor(graph_data['node_type'], dtype=torch.long).to(self.device)
        edge_type = torch.tensor(graph_data['edge_type'], dtype=torch.long).to(self.device)
        edge_timestamp = torch.tensor(graph_data['edge_timestamp'], dtype=torch.float32).to(self.device)
        
        # Forward pass
        outputs = self.model(
            x=x,
            edge_index=edge_index,
            node_type=node_type,
            edge_type=edge_type,
            edge_timestamp=edge_timestamp,
        )
        
        risk = outputs['risk'].item()
        return risk
    
    def _compute_velocity_risk(
        self,
        transactions: List[Transaction],
        current_time: float,
        graph: Optional[nx.Graph],
    ) -> float:
        """Compute velocity-based risk"""
        # Use velocity calculator
        features = self.velocity_calculator.compute_all_features(
            transactions,
            current_time,
            graph,
        )
        
        # Normalize features to risk score
        risk = 0.0
        
        # Kinetic energy component
        if 'kinetic_energy' in features:
            kinetic_norm = min(features['kinetic_energy'] / 1e6, 1.0)
            risk += 0.3 * kinetic_norm
        
        # Burst component
        if 'burst_burst_score' in features:
            burst_norm = min(features['burst_burst_score'] / 5.0, 1.0)
            risk += 0.4 * burst_norm
        
        # Chain velocity component
        if 'chain_chain_velocity' in features:
            chain_norm = min(features['chain_chain_velocity'] / 0.01, 1.0)
            risk += 0.3 * chain_norm
        
        return min(risk, 1.0)
    
    def _compute_behavior_risk(self, behavioral_data: dict) -> float:
        """Compute behavioral biometrics risk"""
        # Extract keystroke data
        if 'hold_times' in behavioral_data and 'flight_times' in behavioral_data:
            # Simulate press/release times from hold/flight times
            hold_times = behavioral_data['hold_times']
            flight_times = behavioral_data['flight_times']
            if not hold_times or not flight_times:
                return 0.5
            
            press_times = [0.0]
            release_times = [hold_times[0]]
            
            for i in range(1, len(hold_times)):
                press_times.append(release_times[-1] + flight_times[i-1] if i-1 < len(flight_times) else release_times[-1] + 0.1)
                release_times.append(press_times[-1] + hold_times[i])
            
            # Analyze keystroke dynamics
            results = analyze_keystroke_data(
                press_times=press_times,
                release_times=release_times,
            )
            
            # Return stress score as risk
            return results.get('stress_score', 0.5)
        
        # If stress score directly provided
        if 'stress_score' in behavioral_data:
            return behavioral_data['stress_score']
        
        return 0.5  # Neutral risk
    
    def _compute_entropy_risk(
        self,
        account: str,
        graph: nx.Graph,
        graph_data: dict,
    ) -> float:
        """Compute entropy-based risk"""
        # Extract node attributes
        node_attributes = graph_data.get('node_attributes', {})
        edge_timestamps = graph_data.get('edge_timestamps', {})
        edge_amounts = graph_data.get('edge_amounts', {})
        current_time = graph_data.get('current_time', None)
        
        # Compute entropy risk
        risk = compute_entropy_risk_score(
            account,
            graph,
            node_attributes,
            edge_timestamps,
            edge_amounts,
            current_time,
        )
        
        return risk
    
    def _make_decision(self, risk_score: float) -> str:
        """
        Make action decision based on risk score
        
        Returns:
            'ALLOW', 'REVIEW', or 'BLOCK'
        """
        if risk_score >= self.threshold_block:
            return 'BLOCK'
        elif risk_score >= self.threshold_review:
            return 'REVIEW'
        else:
            return 'ALLOW'
    
    def _compute_confidence(self, risk_components: Dict[str, float]) -> float:
        """
        Compute confidence in the risk assessment
        
        High variance in components → low confidence
        Low variance → high confidence
        
        Args:
            risk_components: Dictionary of risk components
        
        Returns:
            Confidence score (0-1)
        """
        values = list(risk_components.values())
        variance = np.var(values)
        
        # Map variance to confidence (inverse relationship)
        # Low variance (< 0.05) → high confidence (~1.0)
        # High variance (> 0.25) → low confidence (~0.5)
        confidence = 1.0 / (1.0 + 5 * variance)
        
        return confidence


def compute_risk_score(
    transaction: dict,
    graph_data: Optional[dict] = None,
    biometrics: Optional[dict] = None,
    **kwargs
) -> Dict[str, float]:
    """
    Enhanced risk scorer with graph-based mule account detection
    
    Args:
        transaction: Transaction data
        graph_data: Graph representation
        biometrics: Behavioral biometrics
        **kwargs: Additional parameters (state, etc.)
    
    Returns:
        Risk score dictionary with mule detection
    """
    # Import state from the API module
    from ..api.main import state
    
    risk_score = 0.0
    breakdown = {
        'graph': 0.0,
        'velocity': 0.0,
        'behavior': 0.0,
        'entropy': 0.0,
    }
    
    source_account = transaction.get('source_account')
    target_account = transaction.get('target_account')
    amount = transaction.get('amount', 0)
    
    # 1. GRAPH-BASED RISK (50% weight)
    graph_risk = 0.0
    centrality = None
    graph_view = None
    
    # Check mule accounts even without graph loaded (for demo mode)
    if state.graph_loaded:
        # Check if accounts are in known fraud chains (mule accounts)
        if source_account in state.mule_accounts:
            graph_risk += 0.6
            _inference_logger.warning(
                f"Source account {source_account} is a known mule account",
                event_type="mule_account_detected",
                metadata={"account": source_account, "role": "source"},
            )
        if target_account in state.mule_accounts:
            graph_risk += 0.4
            _inference_logger.warning(
                f"Target account {target_account} is a known mule account",
                event_type="mule_account_detected",
                metadata={"account": target_account, "role": "target"},
            )
        if source_account in state.mule_accounts and target_account in state.mule_accounts:
            graph_risk += 0.3

    if state.graph_loaded and state.transaction_graph:
        # Mule-account penalties are applied in the block above.
        # They are intentionally NOT repeated here — the original code added
        # them a second time, doubling graph_risk for every mule transaction
        # and masking all topology signals (fix for Issue #133).

        if hasattr(state.transaction_graph, "is_active") and state.transaction_graph.is_active:
            graph_view = state.transaction_graph.get_approx_subgraph(source_account, max_hops=2)
        else:
            graph_view = state.transaction_graph

        if source_account in graph_view.nodes:
            # Analyze source account patterns
            out_degree = graph_view.out_degree(source_account)
            in_degree = graph_view.in_degree(source_account)
            
            # STAR PATTERN: High out-degree (distribution hub)
            if out_degree > 20:
                graph_risk += 0.3
                _inference_logger.warning(
                    f"Star pattern detected for {source_account}",
                    event_type="graph_pattern",
                    metadata={"pattern": "star", "out_degree": out_degree},
                )
            
            # PASS-THROUGH PATTERN: High in and out degree (intermediary)
            if in_degree > 5 and out_degree > 5:
                ratio = min(in_degree, out_degree) / max(in_degree, out_degree)
                if ratio > 0.8:  # Balanced in/out suggests pass-through
                    graph_risk += 0.25
                    _inference_logger.warning(
                        f"Pass-through pattern for {source_account}",
                        event_type="graph_pattern",
                        metadata={"pattern": "pass_through", "in_degree": in_degree, "out_degree": out_degree},
                    )
            
            # Check if part of a chain (linear path pattern)
            try:
                descendants = nx.descendants(graph_view, source_account)
                if len(descendants) >= 3:
                    # Check if forms a linear chain
                    subgraph = graph_view.subgraph([source_account] + list(descendants))
                    if nx.is_directed_acyclic_graph(subgraph):
                        graph_risk += 0.2
                        _inference_logger.warning(
                            f"Chain pattern for {source_account}",
                            event_type="graph_pattern",
                            metadata={"pattern": "chain", "descendants": len(descendants)},
                        )
            except Exception as e:
                logger.error(f"Error in chain pattern analysis: {e}")
            
            # Betweenness centrality (key intermediary in network)
            try:
                if centrality is None:
                    centrality = _get_betweenness_centrality(graph_view)
                if source_account in centrality and centrality[source_account] > 0.01:
                    graph_risk += 0.15
                    _inference_logger.warning(
                        f"High centrality for {source_account}",
                        event_type="graph_pattern",
                        metadata={"pattern": "high_centrality"},
                    )
            except Exception as e:
                logger.error(f"Error in centrality analysis: {e}")
    
    graph_risk = min(graph_risk, 1.0)
    breakdown['graph'] = graph_risk
    
    # LATERAL MOVEMENT DETECTION (MITRE ATT&CK TA0008)
    lateral_movement_detected = False
    lateral_movement_reason = ""
    
    if state.graph_loaded and state.transaction_graph:
        G = graph_view
        if G is None:
            if hasattr(state.transaction_graph, "is_active") and state.transaction_graph.is_active:
                G = state.transaction_graph.get_approx_subgraph(source_account, max_hops=2)
            else:
                G = state.transaction_graph
        has_node = G.has_node(source_account) if hasattr(G, "has_node") else source_account in G.nodes if hasattr(G, "nodes") else False

        if has_node:
            try:
                if centrality is None:
                    centrality = _get_betweenness_centrality(G)
                if source_account in centrality:
                    current_score = centrality[source_account]
                    
                    # Get or initialize baseline
                    if source_account not in state.centrality_baseline:
                        state.centrality_baseline[source_account] = []
                    
                    baseline_history = state.centrality_baseline[source_account]
                    
                    if len(baseline_history) >= 3:
                        baseline_avg = np.mean(baseline_history)
                        baseline_std = np.std(baseline_history) if len(baseline_history) > 1 else 0.001
                        
                        # Spike detection: configurable thresholds (from thresholds.yaml)
                        spike_threshold = max(
                            baseline_avg + config_defaults.DEFAULT_LATERAL_MOVEMENT_STD_MULTIPLIER * baseline_std,
                            baseline_avg * config_defaults.DEFAULT_LATERAL_MOVEMENT_THRESHOLD_MULTIPLIER
                        )
                        
                        if current_score > spike_threshold and baseline_avg > 0:
                            lateral_movement_detected = True
                            lateral_movement_reason = f"Lateral movement detected: {source_account} betweenness centrality spiked from baseline {baseline_avg:.4f} to {current_score:.4f} (MITRE ATT&CK TA0008)"
                            graph_risk += config_defaults.DEFAULT_LATERAL_MOVEMENT_RISK_INCREMENT
                            _inference_logger.warning(
                                f"Lateral movement detected for {source_account}",
                                event_type="lateral_movement",
                                metadata={
                                    "baseline_avg": baseline_avg,
                                    "current_score": current_score,
                                },
                            )
                    
                    # Update baseline (rolling window)
                    baseline_history.append(current_score)
                    if len(baseline_history) > state.centrality_window_size:
                        baseline_history.pop(0)
                        
            except Exception as e:
                pass
    
    # 2. VELOCITY RISK (20% weight)
    velocity_risk = 0.0
    
    # Amount-based checks (lowered for demo)
    if amount > 100000:
        velocity_risk += 0.5
    elif amount > 50000:
        velocity_risk += 0.3
    elif amount > 20000:
        velocity_risk += 0.2
    elif amount > 5000:
        velocity_risk += 0.1
    
    # Check against account history if available
    if state.account_profiles and source_account in state.account_profiles:
        profile = state.account_profiles[source_account]
        avg_amount = profile.get('avg_transaction_amount', 0)
        if avg_amount > 0 and amount > 3 * avg_amount:
            velocity_risk += 0.3
            _inference_logger.warning(
                f"Velocity anomaly for {source_account}",
                event_type="velocity_anomaly",
                metadata={"amount": amount, "avg_amount": avg_amount},
            )
    
    velocity_risk = min(velocity_risk, 1.0)
    breakdown['velocity'] = velocity_risk
    
    # 3. BEHAVIORAL RISK (20% weight)
    behavior_risk = 0.0
    
    if biometrics is not None:
        hold_times = biometrics.get('hold_times', [])
        flight_times = biometrics.get('flight_times', [])
        
        if hold_times:
            avg_hold = np.mean(hold_times)
            std_hold = np.std(hold_times)
            
            # Longer hold times suggest hesitation/stress
            if avg_hold > 150:
                behavior_risk += 0.3
            
            # High variance suggests irregular typing
            if std_hold > 50:
                behavior_risk += 0.2
        
        if flight_times:
            avg_flight = np.mean(flight_times)
            
            # Very fast typing could be automated
            if avg_flight < 100:
                behavior_risk += 0.3
            # Very slow could indicate coercion
            elif avg_flight > 300:
                behavior_risk += 0.2
    
    behavior_risk = min(behavior_risk, 1.0)
    breakdown['behavior'] = behavior_risk
    
    # 4. ENTROPY RISK (10% weight)
    entropy_risk = 0.0
    
    # Time-based anomalies (check for late night transactions)
    timestamp = transaction.get('timestamp')
    if timestamp:
        try:
            from datetime import datetime
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = datetime.fromtimestamp(timestamp)
            hour = dt.hour
            # Late night transactions (2 AM - 5 AM) are riskier
            if 2 <= hour <= 5:
                entropy_risk += 0.3
        except Exception as e:
            logger.error(f"Error: {e}")
            pass
    
    # Round amounts are suspicious (lowered for demo)
    if amount == int(amount) and amount % 1000 == 0 and amount >= 5000:
        entropy_risk += 0.2
    
    entropy_risk = min(entropy_risk, 1.0)
    breakdown['entropy'] = entropy_risk

    try:
        threshold_data = load_thresholds('config/thresholds.yaml', validate=True)
        rs = threshold_data.get('risk_scoring', {})
        thresholds = {
            'allow': rs.get('allow', config_defaults.DEFAULT_RISK_THRESHOLDS["allow"]),
            'review': rs.get('review', config_defaults.DEFAULT_RISK_THRESHOLDS["review"]),
            'block': rs.get('block', config_defaults.DEFAULT_RISK_THRESHOLDS["block"]),
        }
    except Exception as e:
        logger.error(f"Error: {e}")
        thresholds = state.config.get('risk_scoring', {}).get('thresholds', {
            'allow': config_defaults.DEFAULT_RISK_THRESHOLDS["allow"],
            'review': config_defaults.DEFAULT_RISK_THRESHOLDS["review"],
            'block': config_defaults.DEFAULT_RISK_THRESHOLDS["block"],
        })

    component_weights = {
        'graph': config_defaults.DEFAULT_COMPONENT_WEIGHTS["graph"],
        'velocity': config_defaults.DEFAULT_COMPONENT_WEIGHTS["velocity"],
        'behavior': config_defaults.DEFAULT_COMPONENT_WEIGHTS["behavior"],
        'entropy': config_defaults.DEFAULT_COMPONENT_WEIGHTS["entropy"],
    }
    central_thresholds = ThresholdConfig(thresholds=thresholds)
    central_scorer = CentralRiskScorer(
        threshold_config=central_thresholds,
        component_weights=component_weights,
    )
    assessment = central_scorer.assess(breakdown)
    
    return {
        'risk_score': assessment.overall_score,
        'decision': assessment.decision,
        'confidence': assessment.confidence,
        'breakdown': breakdown,
        'lateral_movement_detected': lateral_movement_detected,
        'lateral_movement_reason': lateral_movement_reason,
    }
