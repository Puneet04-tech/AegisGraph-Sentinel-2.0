"""
Fraud Pattern Detection Module

Detects specific fraud patterns in transaction graphs:
- Mule rings (circular fund transfer chains)
- Fan-in/Fan-out hubs
- Velocity anomalies
- Temporal fraud chains
"""

import logging
import numpy as np
from typing import Dict, List, Set, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import networkx as nx

from ..scoring import ScoreCalculator

logger = logging.getLogger(__name__)


class FraudPatternDetector:
    """Detects known fraud patterns in transaction graphs"""
    
    def __init__(
        self,
        min_chain_length: int = 3,
        max_hours_between_transfers: int = 24,
    ):
        """
        Args:
            min_chain_length: Minimum transfers to form a suspicious chain
            max_hours_between_transfers: Time threshold for chain detection
        """
        self.min_chain_length = min_chain_length
        self.max_hours_between_transfers = max_hours_between_transfers

    def _txn_value(self, txn, field: str, default=None):
        if isinstance(txn, dict):
            return txn.get(field, default)
        return getattr(txn, field, default)
    
    def detect_mule_rings(
        self,
        transactions: List[Dict],
        reference_time: datetime,
    ) -> List[Dict]:
        """
        Detect mule rings: circular chains of rapid transfers.
        
        A mule ring is identified by:
        1. Chain of accounts: A → B → C → D → ... → back to near-source
        2. Rapid transfers (within time_threshold)
        3. Accounts often NEW (created just before ring activity)
        
        Returns:
            List of detected rings with:
            - ring_accounts: Set of account IDs
            - chain_length: Number of transfers
            - total_amount: Sum transferred
            - risk_score: [0, 1]
            - detected_at: timestamp
        """
        # Build directed transfer graph
        graph = self._build_transfer_graph(transactions)
        
        detected_rings = []
        
        # Search for cycles
        try:
            # Materialize the generator first so a traversal error cannot leave
            # partially processed rings in the output.
            all_cycles = list(nx.simple_cycles(graph))

            for cycle in all_cycles:
                if len(cycle) >= self.min_chain_length:
                    # Extract transactions in this cycle
                    cycle_transactions = self._get_cycle_transactions(
                        graph, cycle, transactions
                    )
                    
                    # Check time constraints
                    if self._verify_timing_constraint(
                        cycle_transactions,
                        self.max_hours_between_transfers
                    ):
                        ring_score = self._score_mule_ring(
                            cycle, graph, cycle_transactions
                        )
                        
                        detected_rings.append({
                            'type': 'MULE_RING',
                            'ring_accounts': cycle,
                            'chain_length': len(cycle),
                            'total_amount': sum(self._txn_value(t, 'amount', 0) for t in cycle_transactions),
                            'risk_score': ring_score,
                            'detected_at': reference_time,
                            'transactions': cycle_transactions,
                        })
        
        except nx.NetworkXError as e:
            logger.warning("Error detecting cycles while enumerating mule rings: %s", e)
        
        return detected_rings
    
    def detect_fan_in_hubs(
        self,
        transactions: List[Dict],
        threshold_incoming: int = 10,
    ) -> List[Dict]:
        """
        Detect accounts with unusually high incoming transfer volume.
        
        Characteristics:
        - Many incoming transfers from diverse sources
        - Transfers often small (trying to blend in)
        - Account often newly created or previously dormant
        
        Returns:
            List of detected hubs with risk scores
        """
        # Count incoming transfers per account
        incoming_counts = defaultdict(list)
        
        for txn in transactions:
            target = self._txn_value(txn, 'target_account')
            if target:
                incoming_counts[target].append(txn)
        
        detected_hubs = []
        
        for account, transfers in incoming_counts.items():
            if len(transfers) >= threshold_incoming:
                # Risk factors
                unique_sources = len(set(self._txn_value(t, 'source_account') for t in transfers))
                avg_amount = np.mean([self._txn_value(t, 'amount', 0) for t in transfers])
                
                hub_score = self._score_fan_in_hub(
                    account,
                    transfers,
                    unique_sources,
                    avg_amount,
                )
                
                detected_hubs.append({
                    'type': 'FAN_IN_HUB',
                    'account': account,
                    'incoming_transfer_count': len(transfers),
                    'unique_sources': unique_sources,
                    'avg_transfer_amount': avg_amount,
                    'total_received': sum(self._txn_value(t, 'amount', 0) for t in transfers),
                    'risk_score': hub_score,
                })
        
        return sorted(detected_hubs, key=lambda x: x['risk_score'], reverse=True)
    
    def detect_fan_out_hubs(
        self,
        transactions: List[Dict],
        threshold_outgoing: int = 15,
    ) -> List[Dict]:
        """
        Detect accounts with unusually high outgoing transfer volume.
        
        Distribution hubs rapidly move funds to many recipients.
        
        Returns:
            List of detected hubs with risk scores
        """
        # Count outgoing transfers per account
        outgoing_counts = defaultdict(list)
        
        for txn in transactions:
            source = self._txn_value(txn, 'source_account')
            if source:
                outgoing_counts[source].append(txn)
        
        detected_hubs = []
        
        for account, transfers in outgoing_counts.items():
            if len(transfers) >= threshold_outgoing:
                unique_targets = len(set(self._txn_value(t, 'target_account') for t in transfers))
                avg_amount = np.mean([self._txn_value(t, 'amount', 0) for t in transfers])
                
                hub_score = self._score_fan_out_hub(
                    account,
                    transfers,
                    unique_targets,
                    avg_amount,
                )
                
                detected_hubs.append({
                    'type': 'FAN_OUT_HUB',
                    'account': account,
                    'outgoing_transfer_count': len(transfers),
                    'unique_targets': unique_targets,
                    'avg_transfer_amount': avg_amount,
                    'total_distributed': sum(self._txn_value(t, 'amount', 0) for t in transfers),
                    'risk_score': hub_score,
                })
        
        return sorted(detected_hubs, key=lambda x: x['risk_score'], reverse=True)
    
    def detect_velocity_anomalies(
        self,
        transactions: List[Dict],
        time_window_hours: int = 1,
        amount_multiplier: float = 5.0,
        transaction_count_threshold: int = 10,
    ) -> List[Dict]:
        """
        Detect sudden spikes in transaction velocity.
        
        Red flags:
        - Account normally inactive suddenly has many transactions
        - Transaction amounts suddenly much larger than historical avg
        - Multiple rapid transactions in short time window
        
        Returns:
            List of anomalies with scores
        """
        anomalies = []
        
        # Group by account and time window
        time_window = timedelta(hours=time_window_hours)
        account_windows = defaultdict(list)
        
        # Sort by timestamp
        sorted_txns = sorted(
            transactions,
            key=lambda x: (
                datetime.fromisoformat(self._txn_value(x, 'timestamp').isoformat())
                if isinstance(self._txn_value(x, 'timestamp'), datetime)
                else self._txn_value(x, 'timestamp')
            )
        )
        
        for txn in sorted_txns:
            account = self._txn_value(txn, 'source_account')
            if account:
                account_windows[account].append(txn)
        
        # Check each account's transaction history
        for account, txns in account_windows.items():
            if len(txns) >= transaction_count_threshold:
                # Calculate metrics
                amounts = [self._txn_value(t, 'amount', 0) for t in txns]
                avg_amount = np.mean(amounts)
                max_amount = np.max(amounts)
                
                # Detect if recent spike
                recent_txns = txns[-5:]  # Last 5 transactions
                recent_avg = np.mean([self._txn_value(t, 'amount', 0) for t in recent_txns])
                
                if recent_avg > avg_amount * amount_multiplier:
                    anomaly_score = min(
                        (recent_avg / avg_amount) / (amount_multiplier * 2),
                        1.0
                    )
                    
                    anomalies.append({
                        'type': 'VELOCITY_ANOMALY',
                        'account': account,
                        'transaction_count_24h': len(txns),
                        'historical_avg_amount': avg_amount,
                        'recent_avg_amount': recent_avg,
                        'spike_multiplier': recent_avg / (avg_amount + 1e-6),
                        'risk_score': anomaly_score,
                    })
        
        return sorted(anomalies, key=lambda x: x['risk_score'], reverse=True)
    
    def detect_temporal_fraud_chains(
        self,
        transactions: List[Dict],
        reference_time: datetime,
    ) -> List[Dict]:
        """
        Detect sequences of events suggesting coordinated fraud:
        1. Account creation
        2. Device/IP linking from suspicious location
        3. Large rapid transfer
        4. Transfer to known mule account
        
        Returns:
            List of detected chains with scores
        """
        chains = []
        
        # This would require more detailed transaction logs including
        # account creation, device linking, etc.
        # For now, simple implementation:
        
        # Sort transactions by timestamp
        sorted_txns = sorted(
            transactions,
            key=lambda x: (
                datetime.fromisoformat(self._txn_value(x, 'timestamp').isoformat())
                if isinstance(self._txn_value(x, 'timestamp'), datetime)
                else self._txn_value(x, 'timestamp')
            )
        )
        
        # Look for rapid sequences
        for i, txn in enumerate(sorted_txns[:-2]):
            source = self._txn_value(txn, 'source_account')
            next_txns = [t for t in sorted_txns[i+1:] if self._txn_value(t, 'source_account') == source]
            
            if len(next_txns) >= 2:
                # Check timing
                ts1_value = self._txn_value(txn, 'timestamp')
                ts2_value = self._txn_value(next_txns[0], 'timestamp')
                ts1 = datetime.fromisoformat(ts1_value.isoformat()) if isinstance(ts1_value, datetime) else ts1_value
                ts2 = datetime.fromisoformat(ts2_value.isoformat()) if isinstance(ts2_value, datetime) else ts2_value
                
                time_diff = (ts2 - ts1).total_seconds() / 3600  # hours
                
                if time_diff < 1:  # Rapid sequence
                    chain_score = min(len(next_txns) / 10.0, 1.0)
                    
                    chains.append({
                        'type': 'TEMPORAL_FRAUD_CHAIN',
                        'account': source,
                        'num_rapid_transfers': len(next_txns),
                        'timespan_hours': time_diff,
                        'risk_score': chain_score,
                    })
        
        return chains
    
    # Helper methods
    
    def _build_transfer_graph(self, transactions: List[Dict]) -> nx.DiGraph:
        """Build directed graph of transfers"""
        graph = nx.DiGraph()
        
        for txn in transactions:
            source = self._txn_value(txn, 'source_account')
            target = self._txn_value(txn, 'target_account')
            amount = self._txn_value(txn, 'amount', 0)
            
            if source and target:
                if graph.has_edge(source, target):
                    graph[source][target]['count'] += 1
                    graph[source][target]['total_amount'] += amount
                else:
                    graph.add_edge(
                        source, target,
                        count=1,
                        total_amount=amount,
                        avg_amount=amount,
                    )
        
        return graph
    
    def _get_cycle_transactions(
        self,
        graph: nx.DiGraph,
        cycle: List,
        transactions: List[Dict],
    ) -> List[Dict]:
        """Extract transactions forming a cycle"""
        cycle_txns = []
        
        for i in range(len(cycle)):
            source = cycle[i]
            target = cycle[(i + 1) % len(cycle)]
            
            # Find transactions between these accounts
            for txn in transactions:
                if (self._txn_value(txn, 'source_account') == source and
                    self._txn_value(txn, 'target_account') == target):
                    cycle_txns.append(txn)
        
        return cycle_txns
    
    def _verify_timing_constraint(
        self,
        transactions: List[Dict],
        max_hours: int,
    ) -> bool:
        """Check if all transactions in chain are within time threshold"""
        if not transactions:
            return False
        
        timestamps = []
        for txn in transactions:
            ts = self._txn_value(txn, 'timestamp')
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts)
            if ts:
                timestamps.append(ts)
        
        if len(timestamps) < 2:
            return True
        
        time_span = (max(timestamps) - min(timestamps)).total_seconds() / 3600
        return time_span <= max_hours
    
    def _score_mule_ring(
        self,
        cycle: List,
        graph: nx.DiGraph,
        transactions: List[Dict],
    ) -> float:
        """
        Score mule ring likelihood.
        
        Factors:
        - Chain length (longer = more suspicious)
        - Rapidness (faster = more suspicious)
        - Uniformity of amounts (mule rings try to be uniform)
        """
        score = 0.0
        
        # Length factor: 3-5 accounts is typical
        length_score = min(len(cycle) / 10.0, 1.0)
        
        # Uniformity of amounts
        uniformity_score = 0.0
        if transactions:
            amounts = [self._txn_value(t, 'amount', 0) for t in transactions]
            cv = np.std(amounts) / (np.mean(amounts) + 1e-6)
            # Low CV (uniform amounts) is suspicious
            uniformity_score = max(0.0, 1.0 - cv)
        
        # Transfer velocity
        velocity_score = 0.0
        if transactions and len(transactions) > 1:
            timestamps = [
                (datetime.fromisoformat(self._txn_value(t, 'timestamp').isoformat())
                 if isinstance(self._txn_value(t, 'timestamp'), datetime)
                 else self._txn_value(t, 'timestamp'))
                for t in transactions if self._txn_value(t, 'timestamp')
            ]
            
            if len(timestamps) > 1:
                time_span = (max(timestamps) - min(timestamps)).total_seconds() / 60
                # Fast transfers (< 30 min for chain) is suspicious
                velocity_score = max(0.0, 1.0 - (time_span / 30.0))

        return ScoreCalculator.aggregate_scores(
            {
                'length': length_score,
                'uniformity': uniformity_score,
                'velocity': velocity_score,
            },
            {
                'length': 0.4,
                'uniformity': 0.4,
                'velocity': 0.2,
            }
        )
    
    def _score_fan_in_hub(
        self,
        account: str,
        transfers: List[Dict],
        unique_sources: int,
        avg_amount: float,
    ) -> float:
        """Score fan-in hub risk"""
        score = 0.0
        
        diversity_score = min(unique_sources / 20.0, 1.0)
        amount_score = 0.3 if avg_amount < 10000 else 0.1
        count_score = min(len(transfers) / 50.0, 1.0)

        return ScoreCalculator.aggregate_scores(
            {
                'diversity': diversity_score,
                'amount': amount_score,
                'count': count_score,
            },
            {
                'diversity': 0.5,
                'amount': 0.3,
                'count': 0.2,
            }
        )
    
    def _score_fan_out_hub(
        self,
        account: str,
        transfers: List[Dict],
        unique_targets: int,
        avg_amount: float,
    ) -> float:
        """Score fan-out hub risk"""
        score = 0.0
        
        diversity_score = min(unique_targets / 30.0, 1.0)
        count_score = min(len(transfers) / 60.0, 1.0)
        total = sum(self._txn_value(t, 'amount', 0) for t in transfers)
        total_score = 0.2 if total > 1000000 else 0.0

        return ScoreCalculator.aggregate_scores(
            {
                'diversity': diversity_score,
                'count': count_score,
                'total': total_score,
            },
            {
                'diversity': 0.5,
                'count': 0.3,
                'total': 0.2,
            }
        )
