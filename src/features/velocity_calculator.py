"""
Transaction Velocity Calculator

Computes velocity-based fraud indicators:
- Transaction velocity (amount/time)
- Chain velocity (distance/time through network)
- Burst detection
- Frequency analysis
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import networkx as nx


@dataclass
class Transaction:
    """Single transaction record"""
    source: str
    target: str
    amount: float
    timestamp: float
    txn_id: str


class VelocityCalculator:
    """
    Calculates transaction velocity features for fraud detection
    
    Key metrics:
    1. Transaction Kinetic Energy: (Δv)² / Δt
    2. Chain Velocity: Network distance / Time
    3. Burst Score: Transactions in time window
    4. Acceleration: Change in velocity
    
    Args:
        time_window: Time window for velocity calculation (seconds)
        burst_window: Time window for burst detection (seconds)
    """
    
    def __init__(
        self,
        time_window: float = 3600.0,  # 1 hour
        burst_window: float = 300.0,   # 5 minutes
    ):
        self.time_window = time_window
        self.burst_window = burst_window
    
    def compute_kinetic_energy(
        self,
        transactions: List[Transaction],
    ) -> float:
        """
        Compute transaction kinetic energy
        
        Formula: E = Σ (Δv_i)² / Δt_i
        
        High kinetic energy indicates rapid fund movement (mule chain)
        
        Args:
            transactions: Sequence of transactions in temporal order
        
        Returns:
            Kinetic energy value
        """
        if len(transactions) < 2:
            return 0.0
        
        energy = 0.0
        for i in range(len(transactions) - 1):
            delta_amount = transactions[i].amount
            delta_time = transactions[i+1].timestamp - transactions[i].timestamp
            
            if delta_time > 0:
                energy += (delta_amount ** 2) / delta_time
        
        return energy
    
    def compute_chain_velocity(
        self,
        transactions: List[Transaction],
        graph: nx.Graph,
    ) -> Dict[str, float]:
        """
        Compute velocity through transaction chain
        
        Measures how quickly funds traverse the social network
        
        Args:
            transactions: Transaction sequence
            graph: Social/transaction graph
        
        Returns:
            Dictionary with velocity metrics
        """
        if len(transactions) < 2:
            return {
                'chain_velocity': 0.0,
                'total_distance': 0,
                'total_time': 0.0,
                'avg_hop_time': 0.0,
            }
        
        # Compute network distances
        total_distance = 0
        for i in range(len(transactions) - 1):
            source = transactions[i].source
            target = transactions[i+1].target
            
            try:
                distance = nx.shortest_path_length(graph, source, target)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                distance = len(transactions)  # Use chain length as proxy
            
            total_distance += distance
        
        # Compute total time
        total_time = transactions[-1].timestamp - transactions[0].timestamp
        
        if total_time == 0:
            return {
                'chain_velocity': float('inf'),
                'total_distance': total_distance,
                'total_time': 0.0,
                'avg_hop_time': 0.0,
            }
        
        # Velocity = distance / time
        velocity = total_distance / total_time
        avg_hop_time = total_time / len(transactions)
        
        return {
            'chain_velocity': velocity,
            'total_distance': total_distance,
            'total_time': total_time,
            'avg_hop_time': avg_hop_time,
        }
    
    def detect_burst(
        self,
        transactions: List[Transaction],
        current_time: float,
    ) -> Dict[str, float]:
        """
        Detect burst patterns (sudden spike in transaction activity)
        
        Args:
            transactions: List of transactions
            current_time: Current timestamp
        
        Returns:
            Dictionary with burst metrics
        """
        # Get transactions in burst window
        recent = [
            t for t in transactions
            if current_time - t.timestamp <= self.burst_window
        ]
        
        # Get transactions in longer window for comparison
        baseline = [
            t for t in transactions
            if current_time - t.timestamp <= self.time_window
        ]
        
        # Count transactions
        burst_count = len(recent)
        baseline_count = len(baseline)
        
        # Expected rate (transactions per second)
        baseline_rate = baseline_count / self.time_window if baseline_count > 0 else 0
        burst_rate = burst_count / self.burst_window if burst_count > 0 else 0
        
        # Burst score (ratio of burst rate to baseline rate)
        if baseline_rate > 0:
            burst_score = burst_rate / baseline_rate
        else:
            burst_score = burst_rate * 10  # Arbitrary multiplier if no baseline
        
        # Amount metrics
        burst_amount = sum(t.amount for t in recent)
        baseline_amount = sum(t.amount for t in baseline)
        
        avg_burst_amount = burst_amount / burst_count if burst_count > 0 else 0
        avg_baseline_amount = baseline_amount / baseline_count if baseline_count > 0 else 0
        
        return {
            'burst_count': burst_count,
            'burst_rate': burst_rate,
            'baseline_rate': baseline_rate,
            'burst_score': burst_score,
            'burst_amount': burst_amount,
            'avg_burst_amount': avg_burst_amount,
            'avg_baseline_amount': avg_baseline_amount,
            'amount_ratio': avg_burst_amount / avg_baseline_amount if avg_baseline_amount > 0 else 0,
        }
    
    def compute_acceleration(
        self,
        transactions: List[Transaction],
    ) -> float:
        """
        Compute transaction acceleration (change in velocity)
        
        Rapid acceleration indicates sudden change in fraud pattern
        
        Args:
            transactions: Transaction sequence
        
        Returns:
            Acceleration value
        """
        if len(transactions) < 3:
            return 0.0
        
        # Split into two halves
        mid = len(transactions) // 2
        first_half = transactions[:mid+1]
        second_half = transactions[mid:]
        
        # Compute velocity for each half
        v1 = self._compute_simple_velocity(first_half)
        v2 = self._compute_simple_velocity(second_half)
        
        # Time difference
        t1 = first_half[-1].timestamp - first_half[0].timestamp
        t2 = second_half[-1].timestamp - second_half[0].timestamp
        total_time = t1 + t2
        
        if total_time == 0:
            return 0.0
        
        # Acceleration = (v2 - v1) / time
        acceleration = (v2 - v1) / total_time
        return acceleration
    
    def _compute_simple_velocity(self, transactions: List[Transaction]) -> float:
        """Compute simple velocity = total_amount / total_time"""
        if len(transactions) < 2:
            return 0.0
        
        total_amount = sum(t.amount for t in transactions)
        total_time = transactions[-1].timestamp - transactions[0].timestamp
        
        if total_time == 0:
            return 0.0
        
        return total_amount / total_time
    
    def compute_all_features(
        self,
        transactions: List[Transaction],
        current_time: float,
        graph: Optional[nx.Graph] = None,
    ) -> Dict[str, float]:
        """
        Compute all velocity-related features
        
        Args:
            transactions: Transaction sequence
            current_time: Current timestamp
            graph: Optional graph for chain velocity
        
        Returns:
            Dictionary with all velocity features
        """
        features = {}
        
        # Kinetic energy
        features['kinetic_energy'] = self.compute_kinetic_energy(transactions)
        
        # Chain velocity
        if graph is not None:
            chain_features = self.compute_chain_velocity(transactions, graph)
            features.update({f'chain_{k}': v for k, v in chain_features.items()})
        
        # Burst detection
        burst_features = self.detect_burst(transactions, current_time)
        features.update({f'burst_{k}': v for k, v in burst_features.items()})
        
        # Acceleration
        features['acceleration'] = self.compute_acceleration(transactions)
        
        # Simple statistics
        if transactions:
            features['total_amount'] = sum(t.amount for t in transactions)
            features['avg_amount'] = np.mean([t.amount for t in transactions])
            features['std_amount'] = np.std([t.amount for t in transactions])
            features['max_amount'] = max(t.amount for t in transactions)
            features['num_transactions'] = len(transactions)
        
        return features


def compute_transaction_velocity_score(
    transactions: List[Transaction],
    current_time: float,
    graph: Optional[nx.Graph] = None,
) -> float:
    """
    Compute overall velocity-based fraud risk score
    
    Args:
        transactions: Transaction sequence
        current_time: Current timestamp
        graph: Optional graph
    
    Returns:
        Velocity risk score (0-1)
    """
    calculator = VelocityCalculator()
    features = calculator.compute_all_features(transactions, current_time, graph)
    
    # Normalize and combine features
    score = 0.0
    
    # High kinetic energy → high risk
    kinetic_norm = min(features['kinetic_energy'] / 1e6, 1.0)
    score += 0.3 * kinetic_norm
    
    # High burst score → high risk
    if 'burst_burst_score' in features:
        burst_norm = min(features['burst_burst_score'] / 5.0, 1.0)
        score += 0.3 * burst_norm
    
    # High chain velocity → high risk
    if 'chain_chain_velocity' in features:
        chain_norm = min(features['chain_chain_velocity'] / 0.01, 1.0)
        score += 0.2 * chain_norm
    
    # High acceleration → high risk
    accel_norm = min(abs(features['acceleration']) / 1000, 1.0)
    score += 0.2 * accel_norm
    
    return min(score, 1.0)
