"""
Fraud Pattern Detection Module

Detects specific fraud patterns in transaction graphs:
- Mule rings (circular fund transfer chains)
- Fan-in/Fan-out hubs
- Velocity anomalies
- Temporal fraud chains
- Layering chains (betweenness centrality)
- Super-mules (PageRank analysis)
- Fraud rings (clique detection)
- Temporal decay weighting

Performance Optimization:
- Graph operations cached with GraphOperationCache
- Supports Redis (production) and in-memory (testing) backends
- Typical cache hit rates: 75-85% for stable transaction graphs
"""

import logging
import numpy as np
import math
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from ..utils.cache import get_graph_cache
import networkx as nx
from dataclasses import dataclass

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
        self.cache = get_graph_cache()  # Initialize graph operation cache

    def _txn_value(self, txn, field: str, default=None):
        if isinstance(txn, dict):
            return txn.get(field, default)
        return getattr(txn, field, default)

    def _normalize_timestamp(self, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                return None
        return None
    
    def detect_mule_rings(
        self,
        transactions: List[Dict],
        reference_time: datetime,
        max_cycle_length: int = 6,
        max_cycle_count: int = 200,
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
            - max_cycle_length: Hard cap on cycle search depth
            - max_cycle_count: Hard cap on emitted cycle candidates
        """
        # Build directed transfer graph
        graph = self._build_transfer_graph(transactions)
        
        # Build (source, target) -> [txn] index once to avoid O(N) rescans per cycle
        txn_index: Dict[tuple, List[Dict]] = defaultdict(list)
        for txn in transactions:
            src = self._txn_value(txn, 'source_account')
            tgt = self._txn_value(txn, 'target_account')
            if src and tgt:
                txn_index[(src, tgt)].append(txn)
        
        detected_rings = []
        
        # Search for cycles with bounded depth and lazy enumeration.
        try:
            for cycle in self._iter_bounded_cycles(
                graph,
                max_cycle_length=max_cycle_length,
                max_cycle_count=max_cycle_count,
            ):
                if len(cycle) >= self.min_chain_length:
                    # Extract transactions in this cycle using pre-built index
                    cycle_transactions = self._get_cycle_transactions(
                        graph, cycle, txn_index
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

    def _iter_bounded_cycles(
        self,
        graph: nx.DiGraph,
        max_cycle_length: int,
        max_cycle_count: int,
    ):
        """Yield unique directed cycles without materializing the full search space."""
        if max_cycle_length < 2 or max_cycle_count < 1:
            return

        seen_cycles: Set[Tuple] = set()
        emitted = 0
        nodes = sorted(graph.nodes(), key=repr)

        for start_node in nodes:
            stack = [(start_node, [start_node], {start_node})]
            while stack:
                current_node, path, path_nodes = stack.pop()
                if len(path) > max_cycle_length:
                    continue

                try:
                    neighbors = list(graph.successors(current_node))
                except nx.NetworkXError:
                    continue

                for neighbor in neighbors:
                    if neighbor == start_node and len(path) >= self.min_chain_length:
                        cycle = path[:]
                        cycle_key = self._canonical_cycle_key(cycle)
                        if cycle_key not in seen_cycles:
                            seen_cycles.add(cycle_key)
                            emitted += 1
                            yield cycle
                            if emitted >= max_cycle_count:
                                return
                        continue

                    if neighbor in path_nodes:
                        continue
                    if len(path) >= max_cycle_length:
                        continue

                    next_path = path + [neighbor]
                    stack.append((neighbor, next_path, path_nodes | {neighbor}))

    @staticmethod
    def _canonical_cycle_key(cycle: List) -> Tuple:
        """Canonicalize a cycle so rotations are deduplicated."""
        if not cycle:
            return tuple()

        rotations = [tuple(cycle[index:] + cycle[:index]) for index in range(len(cycle))]
        return min(rotations, key=lambda candidate: tuple(map(repr, candidate)))
    
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
        # Single pass: collect transfers while incrementally aggregating
        incoming_counts: Dict[str, List[Dict]] = defaultdict(list)
        source_sets: Dict[str, set] = defaultdict(set)
        amount_sums: Dict[str, float] = defaultdict(float)

        for txn in transactions:
            target = self._txn_value(txn, 'target_account')
            if target:
                incoming_counts[target].append(txn)
                source_sets[target].add(self._txn_value(txn, 'source_account'))
                amount_sums[target] += self._txn_value(txn, 'amount', 0)

        detected_hubs = []

        for account, transfers in incoming_counts.items():
            num_transfers = len(transfers)
            if num_transfers >= threshold_incoming:
                unique_sources = len(source_sets[account])
                avg_amount = amount_sums[account] / num_transfers

                hub_score = self._score_fan_in_hub(
                    account,
                    transfers,
                    unique_sources,
                    avg_amount,
                )

                detected_hubs.append({
                    'type': 'FAN_IN_HUB',
                    'account': account,
                    'incoming_transfer_count': num_transfers,
                    'unique_sources': unique_sources,
                    'avg_transfer_amount': avg_amount,
                    'total_received': amount_sums[account],
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
        # Single pass: collect transfers while incrementally aggregating
        outgoing_counts: Dict[str, List[Dict]] = defaultdict(list)
        target_sets: Dict[str, set] = defaultdict(set)
        amount_sums: Dict[str, float] = defaultdict(float)

        for txn in transactions:
            source = self._txn_value(txn, 'source_account')
            if source:
                outgoing_counts[source].append(txn)
                target_sets[source].add(self._txn_value(txn, 'target_account'))
                amount_sums[source] += self._txn_value(txn, 'amount', 0)

        detected_hubs = []

        for account, transfers in outgoing_counts.items():
            num_transfers = len(transfers)
            if num_transfers >= threshold_outgoing:
                unique_targets = len(target_sets[account])
                avg_amount = amount_sums[account] / num_transfers

                hub_score = self._score_fan_out_hub(
                    account,
                    transfers,
                    unique_targets,
                    avg_amount,
                    total_amount=amount_sums[account],
                )

                detected_hubs.append({
                    'type': 'FAN_OUT_HUB',
                    'account': account,
                    'outgoing_transfer_count': num_transfers,
                    'unique_targets': unique_targets,
                    'avg_transfer_amount': avg_amount,
                    'total_distributed': amount_sums[account],
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
        anomalies: List[Dict] = []

        # Build a list of (timestamp, transaction) tuples
        normalized_txns: List[tuple] = []
        for txn in transactions:
            ts = self._normalize_timestamp(self._txn_value(txn, "timestamp"))
            if ts is not None:
                normalized_txns.append((ts, txn))

        # Sort chronologically
        sorted_txns = sorted(normalized_txns, key=lambda item: item[0])

        if not sorted_txns:
            return []

        # Apply time‑window filter (only keep transactions within the last window)
        latest_ts = sorted_txns[-1][0]
        cutoff = latest_ts - timedelta(hours=time_window_hours)
        filtered = [(ts, txn) for ts, txn in sorted_txns if ts >= cutoff]

        # Group transactions by source account within the filtered window
        account_windows: Dict[str, List[Dict]] = defaultdict(list)
        for ts, txn in filtered:
            account = self._txn_value(txn, "source_account")
            if account:
                account_windows[account].append(txn)

        # Evaluate each account for velocity anomalies
        for account, txns in account_windows.items():
            if len(txns) >= transaction_count_threshold:
                amounts = [self._txn_value(t, "amount", 0) for t in txns]
                avg_amount = np.mean(amounts)
                recent_txns = txns[-5:]  # last 5 transactions
                recent_avg = np.mean([self._txn_value(t, "amount", 0) for t in recent_txns])
                if recent_avg > avg_amount * amount_multiplier:
                    anomaly_score = min((recent_avg / avg_amount) / (amount_multiplier * 2), 1.0)
                    anomalies.append({
                        "type": "VELOCITY_ANOMALY",
                        "account": account,
                        "transaction_count_24h": len(txns),
                        "historical_avg_amount": avg_amount,
                        "recent_avg_amount": recent_avg,
                        "spike_multiplier": recent_avg / (avg_amount + 1e-6),
                        "risk_score": anomaly_score,
                    })

        return sorted(anomalies, key=lambda x: x["risk_score"], reverse=True)
        """
        Detect sudden spikes in transaction velocity.

        Red flags:
        - Account normally inactive suddenly has many transactions
        - Transaction amounts suddenly much larger than historical avg
        - Multiple rapid transactions in short time window

        Returns:
            List of anomalies with scores
        """
        anomalies: List[Dict] = []

        # Group by account within the time window
        time_window = timedelta(hours=time_window_hours)
        account_windows: Dict[str, List[Dict]] = defaultdict(list)

        # Normalize timestamps and collect transactions
        normalized_txns: List[tuple] = []
        for txn in transactions:
            ts = self._normalize_timestamp(self._txn_value(txn, "timestamp"))
            if ts is not None:
                normalized_txns.append((ts, txn))

        # Sort transactions chronologically
        sorted_txns = [txn for _, txn in sorted(normalized_txns, key=lambda item: item[0])]

        # Apply time window filtering
        if sorted_txns:
            latest_ts = normalized_txns[-1][0]
            cutoff = latest_ts - time_window
            filtered = [(ts, txn) for ts, txn in normalized_txns if ts >= cutoff]
            # Re‑group by account using filtered list
            for ts, txn in filtered:
                account = self._txn_value(txn, "source_account")
                if account:
                    account_windows[account].append(txn)
        else:
            # No transactions
            filtered = []

        # Evaluate each account's transaction history
        for account, txns in account_windows.items():
            if len(txns) >= transaction_count_threshold:
                amounts = [self._txn_value(t, "amount", 0) for t in txns]
                avg_amount = np.mean(amounts)
                # Recent activity (last 5 transactions)
                recent_txns = txns[-5:]
                recent_avg = np.mean([self._txn_value(t, "amount", 0) for t in recent_txns])
                if recent_avg > avg_amount * amount_multiplier:
                    anomaly_score = min((recent_avg / avg_amount) / (amount_multiplier * 2), 1.0)
                    anomalies.append({
                        "type": "VELOCITY_ANOMALY",
                        "account": account,
                        "transaction_count_24h": len(txns),
                        "historical_avg_amount": avg_amount,
                        "recent_avg_amount": recent_avg,
                        "spike_multiplier": recent_avg / (avg_amount + 1e-6),
                        "risk_score": anomaly_score,
                    })

        return sorted(anomalies, key=lambda x: x["risk_score"], reverse=True)

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
        
        normalized_txns = []
        for txn in transactions:
            ts = self._normalize_timestamp(self._txn_value(txn, 'timestamp'))
            if ts is not None:
                normalized_txns.append((ts, txn))
        sorted_txns = [txn for _, txn in sorted(normalized_txns, key=lambda item: item[0])]

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
        
        normalized_txns = []
        for txn in transactions:
            ts = self._normalize_timestamp(self._txn_value(txn, 'timestamp'))
            if ts is not None:
                normalized_txns.append((ts, txn))

        sorted_txns = [txn for _, txn in sorted(normalized_txns, key=lambda item: item[0])]

        transactions_by_source = defaultdict(list)
        for ts, txn in normalized_txns:
            source = self._txn_value(txn, 'source_account')
            if source:
                transactions_by_source[source].append((ts, txn))

        # Look for rapid sequences using per-account time order
        for source, source_txns in transactions_by_source.items():
            if len(source_txns) >= 3:
                source_txns.sort(key=lambda item: item[0])
                ts1 = source_txns[0][0]
                ts2 = source_txns[1][0]
                time_diff = (ts2 - ts1).total_seconds() / 3600  # hours

                if time_diff < 1:
                    chain_score = min(len(source_txns) / 10.0, 1.0)
                    chains.append({
                        'type': 'TEMPORAL_FRAUD_CHAIN',
                        'account': source,
                        'num_rapid_transfers': len(source_txns) - 1,
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
        txn_index: Dict[tuple, List[Dict]],
    ) -> List[Dict]:
        """Extract transactions forming a cycle using pre-built index."""
        cycle_txns = []
        
        for i in range(len(cycle)):
            source = cycle[i]
            target = cycle[(i + 1) % len(cycle)]
            cycle_txns.extend(txn_index.get((source, target), []))
        
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
            ts = self._normalize_timestamp(self._txn_value(txn, 'timestamp'))
            if ts is not None:
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
            timestamps = []
            for t in transactions:
                ts = self._normalize_timestamp(self._txn_value(t, 'timestamp'))
                if ts is not None:
                    timestamps.append(ts)

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
        total_amount: float = 0.0,
    ) -> float:
        """Score fan-out hub risk"""
        score = 0.0
        
        diversity_score = min(unique_targets / 30.0, 1.0)
        count_score = min(len(transfers) / 60.0, 1.0)
        total_score = 0.2 if total_amount > 1000000 else 0.0

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

    # ============================================================================
    # CENTRALITY ANALYSIS METHODS (Issue #5 Enhancement)
    # ============================================================================

    def detect_layering_chains(
        self,
        transactions: List[Dict],
        reference_time: Optional[datetime] = None,
        betweenness_threshold: float = 0.6,
    ) -> List[Dict]:
        """
        Detect money laundering layering chains using betweenness centrality.
        
        Layering chains are linear A→B→C→D structures where intermediate
        accounts (B, C) have high betweenness centrality (act as bridges).
        
        Args:
            transactions: List of transaction dictionaries
            reference_time: Reference time for scoring (default: now)
            betweenness_threshold: Minimum betweenness to flag (0.0-1.0)
        
        Returns:
            List of detected layering chains with scores
        """
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        
        graph = self._build_transfer_graph(transactions)
        
        if len(graph.nodes()) < 3:
            return []
        
        detected_chains = []
        
        try:
            # Calculate betweenness centrality (cached for performance)
            betweenness = self.cache.cache_betweenness_centrality(
                graph, weight='total_amount', ttl=900
            )
            
            # Identify high-betweenness nodes (potential intermediaries)
            intermediaries = {
                node: score for node, score in betweenness.items()
                if score >= betweenness_threshold
            }
            
            if not intermediaries:
                return []
            
            # Find linear chains through intermediaries
            for intermediate in intermediaries:
                predecessors = list(graph.predecessors(intermediate))
                successors = list(graph.successors(intermediate))
                
                for pred in predecessors[:3]:  # Limit to avoid explosion
                    for succ in successors[:3]:
                        # Found A → B → C pattern (B is intermediate)
                        chain = [pred, intermediate, succ]
                        chain_txns = self._get_chain_transactions(chain, graph, transactions)
                        
                        if chain_txns and self._verify_timing_constraint(chain_txns, 24):
                            chain_score = self._score_layering_chain(
                                chain, graph, chain_txns, betweenness[intermediate]
                            )
                            
                            detected_chains.append({
                                'type': 'LAYERING_CHAIN',
                                'chain_accounts': chain,
                                'chain_length': 3,
                                'betweenness_scores': {
                                    node: betweenness.get(node, 0.0) for node in chain
                                },
                                'total_amount': sum(
                                    self._txn_value(t, 'amount', 0) for t in chain_txns
                                ),
                                'risk_score': chain_score,
                                'detected_at': reference_time,
                                'pattern': 'LINEAR_LAYERING',
                            })
        
        except nx.NetworkXError as e:
            logger.warning("Error in layering chain detection: %s", e)
        
        return sorted(detected_chains, key=lambda x: x['risk_score'], reverse=True)

    def detect_super_mules(
        self,
        transactions: List[Dict],
        reference_time: Optional[datetime] = None,
        pagerank_threshold: float = 0.7,
        volume_threshold_percentile: float = 0.75,
    ) -> List[Dict]:
        """
        Identify super-mules using PageRank analysis.
        
        Super-mules have:
        - High PageRank (disproportionate influence in fraud network)
        - High transaction volume
        - Incoming transfers from high-value sources
        
        Args:
            transactions: List of transaction dictionaries
            reference_time: Reference time for scoring
            pagerank_threshold: Minimum PageRank to flag (normalized 0-1)
            volume_threshold_percentile: Volume percentile threshold (0-1)
        
        Returns:
            List of detected super-mules with scores
        """
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        
        graph = self._build_transfer_graph(transactions)
        
        if len(graph.nodes()) < 2:
            return []
        
        detected_super_mules = []
        
        try:
            # Calculate PageRank (cached for performance)
            pagerank = self.cache.cache_pagerank(
                graph, alpha=0.85, weight='total_amount', max_iter=100, ttl=900
            )
            
            # Normalize PageRank scores
            max_pr = max(pagerank.values()) if pagerank else 1.0
            normalized_pr = {k: v / max_pr for k, v in pagerank.items()}
            
            # Calculate transaction volumes per account (incoming)
            incoming_volumes = defaultdict(float)
            for source, target, data in graph.edges(data=True):
                incoming_volumes[target] += data.get('total_amount', 0)
            
            # Normalize volumes
            max_volume = max(incoming_volumes.values()) if incoming_volumes else 1.0
            normalized_volumes = {
                k: v / max_volume for k, v in incoming_volumes.items()
            }
            
            # Find super-mules: high PageRank + high volume
            for account, pr_score in normalized_pr.items():
                in_degree = graph.in_degree(account)
                
                # Filter out single-transfer false positives
                # A true super-mule must have multiple incoming transfers
                if pr_score >= pagerank_threshold and in_degree > 1:
                    volume = normalized_volumes.get(account, 0.0)
                    
                    # Score: weighted combination of PageRank and volume
                    super_mule_score = (0.6 * pr_score) + (0.4 * volume)
                    
                    total_received = incoming_volumes.get(account, 0.0)
                    
                    detected_super_mules.append({
                        'type': 'SUPER_MULE',
                        'account': account,
                        'pagerank_score': float(pr_score),
                        'volume_score': float(volume),
                        'combined_score': float(super_mule_score),
                        'incoming_transfers': int(in_degree),
                        'total_received': float(total_received),
                        'risk_score': float(super_mule_score),
                        'detected_at': reference_time,
                        'pattern': 'HIGH_INFLUENCE_HUB',
                    })
        
        except nx.NetworkXError as e:
            logger.warning("Error in super-mule detection: %s", e)
        
        return sorted(detected_super_mules, key=lambda x: x['risk_score'], reverse=True)

    def detect_fraud_rings(
        self,
        transactions: List[Dict],
        reference_time: Optional[datetime] = None,
        min_clique_size: int = 3,
        max_clique_size: int = 8,
        density_threshold: float = 0.75,
    ) -> List[Dict]:
        """
        Detect closed fraud rings using clique detection.
        
        Fraud rings are near-complete subgraphs where:
        - All or most accounts send to all others (high density)
        - Transfers are synchronized in time
        - Accounts are new or previously dormant
        
        Args:
            transactions: List of transaction dictionaries
            reference_time: Reference time for scoring
            min_clique_size: Minimum clique size to consider
            max_clique_size: Maximum clique size (computational limit)
            density_threshold: Minimum edge density (0.0-1.0)
        
        Returns:
            List of detected fraud rings with scores
        """
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        
        # Build undirected graph for clique detection
        graph = self._build_transfer_graph(transactions)
        undirected_graph = graph.to_undirected()
        
        if len(undirected_graph.nodes()) < min_clique_size:
            return []
        
        # Build (source, target) -> txn index once to avoid O(N) rescans per clique
        txn_map: Dict[tuple, Dict] = {}
        for txn in transactions:
            src = self._txn_value(txn, 'source_account')
            dst = self._txn_value(txn, 'target_account')
            if src and dst:
                txn_map[(src, dst)] = txn
        
        detected_rings = []
        
        try:
            pruned_graph = self._prune_graph_for_clique_search(
                undirected_graph,
                min_clique_size=min_clique_size,
            )
            if len(pruned_graph.nodes()) < min_clique_size:
                return []

            # Find all maximal cliques on the pruned subgraph.
            cliques_cached = self.cache.cache_find_cliques(pruned_graph, ttl=900)
            cliques = [list(c) for c in cliques_cached]  # Convert frozensets back to lists
            
            for clique in cliques:
                if min_clique_size <= len(clique) <= max_clique_size:
                    # Calculate clique density
                    clique_subgraph = undirected_graph.subgraph(clique)
                    density = nx.density(clique_subgraph)
                    
                    if density >= density_threshold:
                        # Get transactions within this clique using pre-built index
                        clique_txns = self._get_clique_transactions(
                            clique, graph, txn_map
                        )
                        
                        if clique_txns:
                            # Score the fraud ring
                            ring_score = self._score_fraud_ring_clique(
                                clique, clique_subgraph, clique_txns,
                                density, reference_time
                            )
                            
                            detected_rings.append({
                                'type': 'FRAUD_RING',
                                'ring_accounts': clique,
                                'ring_size': len(clique),
                                'density': float(density),
                                'total_amount': sum(
                                    self._txn_value(t, 'amount', 0) for t in clique_txns
                                ),
                                'transaction_count': len(clique_txns),
                                'risk_score': float(ring_score),
                                'detected_at': reference_time,
                                'pattern': 'CLOSED_FRAUD_RING',
                                'sync_score': float(
                                    self._calculate_ring_synchronization(clique_txns)
                                ),
                            })
        
        except nx.NetworkXError as e:
            logger.warning("Error in fraud ring detection: %s", e)
        
        return sorted(detected_rings, key=lambda x: x['risk_score'], reverse=True)

    def _prune_graph_for_clique_search(
        self,
        graph: nx.Graph,
        min_clique_size: int,
    ) -> nx.Graph:
        """
        Prune nodes that cannot belong to a clique of size min_clique_size.

        A node in a clique of size k must have degree at least k - 1 inside the
        induced subgraph, so we first remove nodes below that bound and then
        apply a k-core reduction to collapse the remaining low-degree fringe.
        """
        if min_clique_size <= 2 or len(graph) == 0:
            return graph

        required_degree = min_clique_size - 1
        degree_filtered = graph.subgraph(
            [node for node, degree in graph.degree() if degree >= required_degree]
        ).copy()

        if len(degree_filtered) < min_clique_size:
            return degree_filtered

        try:
            return nx.k_core(degree_filtered, k=required_degree)
        except nx.NetworkXError:
            # If the graph becomes too sparse after filtering, fall back to the
            # degree-pruned subgraph rather than failing the entire detector.
            return degree_filtered

    def apply_temporal_decay_to_pattern(
        self,
        pattern: Dict,
        decay_rate: float = 0.1,
        reference_time: Optional[datetime] = None,
    ) -> Dict:
        """
        Apply temporal decay weighting to a fraud pattern.
        
        Recent suspicious activity weighted more than historical.
        Decay formula: weight = e^(-decay_rate × days_elapsed)
        
        Args:
            pattern: Detected fraud pattern dictionary
            decay_rate: Exponential decay rate (higher = faster decay)
            reference_time: Reference time (default: now)
        
        Returns:
            Pattern with adjusted risk score and decay weight
        """
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        
        detected_at = pattern.get('detected_at')
        if not detected_at:
            return pattern
        
        # Ensure datetime objects are timezone-aware
        if isinstance(detected_at, datetime) and detected_at.tzinfo is None:
            detected_at = detected_at.replace(tzinfo=timezone.utc)
        if reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)
        
        days_elapsed = (reference_time - detected_at).days
        decay_weight = self._calculate_temporal_decay(
            detected_at, decay_rate, reference_time
        )
        
        # Adjust risk score
        original_score = pattern.get('risk_score', 0.0)
        decayed_score = original_score * decay_weight
        
        pattern['temporal_decay_factor'] = float(decay_weight)
        pattern['original_risk_score'] = float(original_score)
        pattern['risk_score'] = float(decayed_score)
        pattern['days_elapsed'] = int(days_elapsed)
        
        return pattern

    # ============================================================================
    # Centrality Helper Methods
    # ============================================================================

    def _calculate_temporal_decay(
        self,
        timestamp: datetime,
        decay_rate: float = 0.1,
        reference_time: Optional[datetime] = None,
    ) -> float:
        """
        Calculate exponential temporal decay weight.
        
        Recent events (today) = 1.0
        Older events = progressively lower weight
        
        decay = e^(-decay_rate × days_elapsed)
        
        Args:
            timestamp: Event timestamp
            decay_rate: Decay constant (default 0.1)
            reference_time: Reference time (default: now)
        
        Returns:
            Weight 0.0-1.0 (higher = more recent)
        """
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        
        # Ensure timezone-aware
        if isinstance(timestamp, datetime) and timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        if reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)
        
        days_elapsed = (reference_time - timestamp).days
        weight = math.exp(-decay_rate * days_elapsed)
        
        return max(0.0, min(1.0, weight))

    def _score_layering_chain(
        self,
        chain: List[str],
        graph: nx.DiGraph,
        transactions: List[Dict],
        intermediate_betweenness: float,
    ) -> float:
        """
        Score layering chain risk.
        
        Factors:
        - Betweenness of intermediate nodes
        - Uniform transfer amounts (deliberate obfuscation)
        - Rapid transfers (chain completion)
        """
        # Betweenness factor (higher = more bridging)
        betweenness_score = min(intermediate_betweenness, 1.0)
        
        # Uniformity of amounts
        uniformity_score = 0.0
        if transactions:
            amounts = [self._txn_value(t, 'amount', 0) for t in transactions]
            if len(amounts) > 1:
                cv = np.std(amounts) / (np.mean(amounts) + 1e-6)
                # Low CV (uniform) is suspicious
                uniformity_score = max(0.0, 1.0 - min(cv, 1.0))
        
        # Transfer speed
        velocity_score = 0.0
        if transactions and len(transactions) > 1:
            timestamps = []
            for t in transactions:
                ts = self._txn_value(t, 'timestamp')
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts)
                if ts:
                    timestamps.append(ts)
            
            if len(timestamps) > 1:
                time_span_hours = (max(timestamps) - min(timestamps)).total_seconds() / 3600
                # Rapid chain (< 6 hours) is suspicious
                velocity_score = max(0.0, 1.0 - (time_span_hours / 6.0))
        
        return ScoreCalculator.aggregate_scores(
            {
                'betweenness': betweenness_score,
                'uniformity': uniformity_score,
                'velocity': velocity_score,
            },
            {
                'betweenness': 0.5,
                'uniformity': 0.3,
                'velocity': 0.2,
            }
        )

    def _score_fraud_ring_clique(
        self,
        clique: List[str],
        clique_graph: nx.Graph,
        transactions: List[Dict],
        density: float,
        reference_time: datetime,
    ) -> float:
        """
        Score fraud ring (clique) risk.
        
        Factors:
        - Clique density (completeness)
        - Transaction synchronization
        - Account age (new accounts higher risk)
        """
        # Density factor (higher = more complete ring)
        density_score = density
        
        # Synchronization: transactions clustered in time
        sync_score = self._calculate_ring_synchronization(transactions)
        
        # Size factor: larger rings more complex/risky
        size_score = min(len(clique) / 10.0, 1.0)
        
        return ScoreCalculator.aggregate_scores(
            {
                'density': density_score,
                'synchronization': sync_score,
                'size': size_score,
            },
            {
                'density': 0.5,
                'synchronization': 0.3,
                'size': 0.2,
            }
        )

    def _calculate_ring_synchronization(
        self,
        transactions: List[Dict],
    ) -> float:
        """
        Measure synchronization of ring transfers.
        
        Coordinated fraud shows clustered timestamps.
        Random transfers would be spread across time.
        
        Returns:
            Score 0.0-1.0 (higher = more synchronized)
        """
        if not transactions or len(transactions) < 2:
            return 0.0
        
        # Extract timestamps
        timestamps = []
        for t in transactions:
            ts = self._txn_value(t, 'timestamp')
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    continue
            if isinstance(ts, datetime):
                timestamps.append(ts)
        
        if len(timestamps) < 2:
            return 0.0
        
        # Calculate time between consecutive transfers
        timestamps.sort()
        time_diffs = []
        for i in range(len(timestamps) - 1):
            diff = (timestamps[i + 1] - timestamps[i]).total_seconds() / 60  # minutes
            time_diffs.append(diff)
        
        if not time_diffs:
            return 0.0
        
        # High clustering = low variance in time differences
        mean_diff = np.mean(time_diffs)
        std_diff = np.std(time_diffs)
        
        # Coefficient of variation (lower CV = more synchronized)
        cv = std_diff / (mean_diff + 1e-6)
        
        # Convert to sync score: 0-1 (0=random, 1=perfect sync)
        sync_score = max(0.0, 1.0 - min(cv, 1.0))
        
        return sync_score

    def _get_chain_transactions(
        self,
        chain: List[str],
        graph: nx.DiGraph,
        transactions: List[Dict],
    ) -> List[Dict]:
        """Extract transactions forming a linear chain"""
        # Build a (source, target) -> [txns] index for O(1) lookups
        index: Dict[tuple, List[Dict]] = defaultdict(list)
        for txn in transactions:
            src = self._txn_value(txn, 'source_account')
            tgt = self._txn_value(txn, 'target_account')
            if src and tgt:
                index[(src, tgt)].append(txn)

        chain_txns = []
        for i in range(len(chain) - 1):
            chain_txns.extend(index.get((chain[i], chain[i + 1]), []))
        return chain_txns

    def _get_clique_transactions(
        self,
        clique: List[str],
        graph: nx.DiGraph,
        txn_map: Dict[tuple, Dict],
    ) -> List[Dict]:
        """Extract all transactions within a clique using pre-built index."""
        clique_set = set(clique)
        clique_txns = []
        for u, v in graph.edges():
            if u in clique_set and v in clique_set:
                txn = txn_map.get((u, v))
                if txn:
                    clique_txns.append(txn)
        
        return clique_txns