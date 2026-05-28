"""
Transaction Velocity Calculator

Computes velocity-based fraud indicators:
- Transaction velocity (amount/time)
- Chain velocity (distance/time through network)
- Burst detection
- Frequency analysis
"""
# Working on velocity-based fraud detection improvements

import numpy as np
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import networkx as nx
import pandas as pd


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

    def calculate_kinetic_energy(self, transactions) -> float:
        """Compatibility wrapper for legacy callers."""
        return self.compute_kinetic_energy(self._normalize_transactions(transactions))

    def calculate_chain_velocity(self, transactions, graph: Optional[nx.Graph] = None) -> float:
        """Compatibility wrapper returning the chain velocity scalar."""
        normalized = self._normalize_transactions(transactions)
        if graph is None:
            if len(normalized) < 2:
                return 0.0
            total_time = normalized[-1].timestamp - normalized[0].timestamp
            if total_time <= 0:
                return float(len(normalized) - 1)
            return float((len(normalized) - 1) / total_time)

        chain_features = self.compute_chain_velocity(normalized, graph)
        return float(chain_features['chain_velocity'])
    
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
            delta_amount = transactions[i + 1].amount - transactions[i].amount
            delta_time = transactions[i + 1].timestamp - transactions[i].timestamp

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
        
        # Compute network distances with a per-source SSSP cache so repeated
        # adjacent pairs do not retraverse the graph.
        shortest_path_cache: Dict[str, Dict[str, int]] = {}
        total_distance = 0
        for i in range(len(transactions) - 1):
            source = transactions[i].source
            target = transactions[i+1].target
            
            if source not in shortest_path_cache:
                try:
                    shortest_path_cache[source] = nx.single_source_shortest_path_length(graph, source)
                except nx.NodeNotFound:
                    shortest_path_cache[source] = {}

            distance = shortest_path_cache[source].get(target)
            if distance is None:
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
        normalized = self._normalize_transactions(transactions)

        # Backward-compatible overload: detect_burst(recent, historical) -> float.
        if not isinstance(current_time, (int, float)):
            recent = normalized
            baseline = self._normalize_transactions(current_time)
            return self._burst_score_from_windows(recent, baseline)

        # Get transactions in burst window
        recent = [
            t for t in normalized
            if current_time - t.timestamp <= self.burst_window
        ]

        # Get transactions in longer window for comparison
        baseline = [
            t for t in normalized
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

    def _normalize_transactions(self, transactions) -> List[Transaction]:
        """Normalize lists, dicts, and DataFrames to Transaction records."""
        if transactions is None:
            return []

        if isinstance(transactions, pd.DataFrame):
            records = transactions.to_dict(orient='records')
        elif isinstance(transactions, dict):
            records = [transactions]
        else:
            records = list(transactions)

        normalized = []
        for index, txn in enumerate(records):
            if isinstance(txn, Transaction):
                normalized.append(txn)
                continue

            source = txn.get('source') or txn.get('from') or txn.get('from_account') or txn.get('account_id') or txn.get('source_account') or f'SRC_{index}'
            target = txn.get('target') or txn.get('to') or txn.get('to_account') or txn.get('target_account') or f'TGT_{index}'
            amount = float(txn.get('amount', 0.0))
            timestamp = self._normalize_timestamp(txn.get('timestamp'), float(index))
            txn_id = txn.get('txn_id') or txn.get('transaction_id') or f'txn_{index}'
            normalized.append(Transaction(source=source, target=target, amount=amount, timestamp=timestamp, txn_id=txn_id))

        return normalized

    def _normalize_timestamp(self, value, fallback: float) -> float:
        """Coerce timestamp inputs into a float seconds-since-epoch value."""
        if value is None:
            return fallback

        if isinstance(value, (int, float)):
            return float(value)

        if isinstance(value, datetime):
            dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
            return float(dt.timestamp())

        if hasattr(value, "to_pydatetime"):
            try:
                dt = value.to_pydatetime()
                dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                return float(dt.timestamp())
            except Exception:
                return fallback

        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                return float(dt.timestamp())
            except ValueError:
                return fallback

        return fallback

    def _burst_score_from_windows(self, recent: List[Transaction], baseline: List[Transaction]) -> float:
        """Return a scalar burst score for compatibility callers."""
        if not recent:
            return 0.0
        current_time = max(t.timestamp for t in recent)
        recent_window = [t for t in recent if current_time - t.timestamp <= self.burst_window]
        baseline_window = baseline if baseline else recent
        burst_count = len(recent_window)
        baseline_count = len(baseline_window)
        burst_rate = burst_count / self.burst_window if burst_count > 0 else 0.0
        baseline_rate = baseline_count / self.time_window if baseline_count > 0 else 0.0
        if baseline_rate > 0:
            return float(burst_rate / baseline_rate)
        return float(burst_rate * 10)
    
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
