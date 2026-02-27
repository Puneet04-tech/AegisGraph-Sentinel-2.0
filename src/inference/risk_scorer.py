"""
Risk Scoring Pipeline

Combines multiple fraud signals into a comprehensive risk score:
1. Graph-based risk (HTGNN)
2. Velocity-based risk
3. Behavioral biometrics risk  
4. Entropy-based risk
"""

import torch
import numpy as np
from typing import Dict, Optional, Tuple, List
import networkx as nx

from ..models.risk_model import FraudDetectionModel
from ..features.velocity_calculator import VelocityCalculator, Transaction
from ..features.behavioral_biometrics import analyze_keystroke_data
from ..features.entropy_calculator import compute_entropy_risk_score


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
        self.device = device or torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        self.model.to(self.device)
        self.model.eval()
        
        # Risk scoring weights
        weights = config.get('risk_scoring', {}).get('weights', {})
        self.w_graph = weights.get('graph', 0.50)
        self.w_velocity = weights.get('velocity', 0.20)
        self.w_behavior = weights.get('behavior', 0.20)
        self.w_entropy = weights.get('entropy', 0.10)
        
        # Thresholds
        thresholds = config.get('risk_scoring', {}).get('thresholds', {})
        self.threshold_block = thresholds.get('block', 0.90)
        self.threshold_review = thresholds.get('review', 0.70)
        self.threshold_allow = thresholds.get('allow', 0.50)
        
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
        
        # Weighted combination
        final_risk = (
            self.w_graph * risk_components['graph'] +
            self.w_velocity * risk_components['velocity'] +
            self.w_behavior * risk_components['behavior'] +
            self.w_entropy * risk_components['entropy']
        )
        
        # Decision
        decision = self._make_decision(final_risk)
        
        # Confidence (based on variance of components)
        confidence = self._compute_confidence(risk_components)
        
        return {
            'risk_score': float(final_risk),
            'decision': decision,
            'confidence': float(confidence),
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
    
    if state.graph_loaded and state.transaction_graph:
        # Check if accounts are in known fraud chains
        if source_account in state.mule_accounts:
            graph_risk += 0.6
            print(f"🚨 Alert: Source account {source_account} is a known mule account!")
        if target_account in state.mule_accounts:
            graph_risk += 0.4
            print(f"🚨 Alert: Target account {target_account} is a known mule account!")
        
        # Check graph topology patterns
        G = state.transaction_graph
        
        if source_account in G.nodes:
            # Analyze source account patterns
            out_degree = G.out_degree(source_account)
            in_degree = G.in_degree(source_account)
            
            # STAR PATTERN: High out-degree (distribution hub)
            if out_degree > 20:
                graph_risk += 0.3
                print(f"⚠️ Star pattern detected: {source_account} has {out_degree} outgoing connections")
            
            # PASS-THROUGH PATTERN: High in and out degree (intermediary)
            if in_degree > 5 and out_degree > 5:
                ratio = min(in_degree, out_degree) / max(in_degree, out_degree)
                if ratio > 0.8:  # Balanced in/out suggests pass-through
                    graph_risk += 0.25
                    print(f"⚠️ Pass-through pattern: {source_account} (in={in_degree}, out={out_degree})")
            
            # Check if part of a chain (linear path pattern)
            try:
                descendants = nx.descendants(G, source_account)
                if len(descendants) >= 3:
                    # Check if forms a linear chain
                    subgraph = G.subgraph([source_account] + list(descendants))
                    if nx.is_directed_acyclic_graph(subgraph):
                        graph_risk += 0.2
                        print(f"⚠️ Chain pattern: {source_account} feeds into {len(descendants)} accounts")
            except:
                pass
            
            # Betweenness centrality (key intermediary in network)
            try:
                centrality = nx.betweenness_centrality(G, k=min(100, G.number_of_nodes()))
                if source_account in centrality and centrality[source_account] > 0.01:
                    graph_risk += 0.15
                    print(f"⚠️ High centrality: {source_account} is a network hub")
            except:
                pass
    
    graph_risk = min(graph_risk, 1.0)
    breakdown['graph'] = graph_risk
    
    # 2. VELOCITY RISK (20% weight)
    velocity_risk = 0.0
    
    # Amount-based checks
    if amount > 100000:
        velocity_risk += 0.5
    elif amount > 50000:
        velocity_risk += 0.3
    elif amount > 10000:
        velocity_risk += 0.1
    
    # Check against account history if available
    if state.account_profiles and source_account in state.account_profiles:
        profile = state.account_profiles[source_account]
        avg_amount = profile.get('avg_transaction_amount', 0)
        if avg_amount > 0 and amount > 3 * avg_amount:
            velocity_risk += 0.3
            print(f"⚠️ Velocity anomaly: Amount {amount} is 3x profile average {avg_amount}")
    
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
        except:
            pass
    
    # Round amounts are suspicious
    if amount == int(amount) and amount % 10000 == 0:
        entropy_risk += 0.2
    
    entropy_risk = min(entropy_risk, 1.0)
    breakdown['entropy'] = entropy_risk
    
    # Combine risks with weights
    risk_score = (
        0.50 * graph_risk +
        0.20 * velocity_risk +
        0.20 * behavior_risk +
        0.10 * entropy_risk
    )
    
    # Make decision
    if risk_score >= 0.70:
        decision = 'BLOCK'
    elif risk_score >= 0.40:
        decision = 'REVIEW'
    else:
        decision = 'ALLOW'
    
    return {
        'risk_score': risk_score,
        'decision': decision,
        'confidence': 0.85,
        'breakdown': breakdown,
    }
