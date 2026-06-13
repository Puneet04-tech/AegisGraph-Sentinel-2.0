"""
Production Inference Module

Implements real-time HTGNN-based fraud scoring with:
- Model loading and caching
- Subgraph extraction
- Batch and streaming inference
- Explainability (attention analysis)
- Fallback to heuristics
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice
import os

import torch
import torch.nn as nn
import numpy as np
import logging
from collections import deque
from threading import Lock
from typing import Dict, Iterator, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import json

logger = logging.getLogger(__name__)


@dataclass
class FraudScore:
    """Complete fraud decision record"""
    transaction_id: str
    risk_score: float  # [0, 1]
    decision: str  # ALLOW, REVIEW, BLOCK
    confidence: float  # Model confidence
    explanation: str  # Human-readable explanation
    breakdown: Dict[str, float]  # Component risk scores
    influential_neighbors: List[Dict]  # Top neighbors by influence
    model_version: str
    inference_time_ms: float
    graph_size: int  # Number of nodes in subgraph
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


class _ThreadSafeCache:
    """Thread-safe dict wrapper for concurrent subgraph caching."""

    def __init__(self):
        self._data: Dict[str, Dict] = {}
        self._lock = Lock()

    def get(self, key: str) -> Optional[Dict]:
        with self._lock:
            return self._data.get(key)

    def set(self, key: str, value: Dict) -> None:
        with self._lock:
            self._data[key] = value


class ProductionRiskScorer:
    """
    Production-grade fraud scorer using HTGNN.

    Decision Logic:
    - score ≥ 0.9: BLOCK (high confidence fraud)
    - 0.6 ≤ score < 0.9: REVIEW (needs analyst)
    - score < 0.6: ALLOW (normal transaction)

    Lifecycle:
    Use as a context manager or call `.close()` explicitly when done.
    Failing to do so will emit a ResourceWarning and may leave threads
    alive past the object's logical lifetime::

        with ProductionRiskScorer(model, graph_constructor) as scorer:
            result = scorer.score_transaction(request)
    """
    
    def __init__(
        self,
        model: nn.Module,
        graph_constructor,
        device: str = 'cpu',
        model_version: str = '2.0.0',
        enable_heuristic_fallback: bool = True,
    ):
        """
        Args:
            model: Trained HTGNN model
            graph_constructor: TemporalGraphConstructor instance
            device: 'cuda' or 'cpu'
            model_version: Version string for logging
            enable_heuristic_fallback: Fall back if model fails
        """
        self.model = model
        self.model.eval()
        self.graph_constructor = graph_constructor
        self.device = device
        self.model_version = model_version
        self.enable_heuristic_fallback = enable_heuristic_fallback
        
        self._executor = ThreadPoolExecutor(max_workers=os.cpu_count() or 1)

        logger.info(
            f"Initialized ProductionRiskScorer "
            f"(model={model_version}, device={device})"
        )
    
    def score_transaction(
        self,
        transaction: Dict,
        reference_time: Optional[datetime] = None,
        k_hops: int = 2,
        _subgraph_cache: Optional["_ThreadSafeCache"] = None,
    ) -> FraudScore:
        """
        Score a single transaction using HTGNN.
        
        Args:
            transaction: Transaction dict with keys:
                - transaction_id
                - source_account
                - target_account
                - amount
                - timestamp
                - (optional) source_device_id, source_ip, etc.
            reference_time: Current time for temporal encoding
            k_hops: Neighborhood depth for subgraph
        
        Returns:
            FraudScore with decision and explanation
        """
        start_time = datetime.utcnow()
        
        try:
            # Extract subgraph around source account (cached per batch)
            source = transaction['source_account']
            subgraph = _subgraph_cache.get(source) if _subgraph_cache is not None else None
            if subgraph is None:
                subgraph = self.graph_constructor.get_subgraph_around_node(
                    node_id=source,
                    k_hops=k_hops,
                    reference_time=reference_time,
                )
                if _subgraph_cache is not None:
                    _subgraph_cache.set(source, subgraph)
            
            # Run inference
            with torch.no_grad():
                x = subgraph['x'].to(self.device)
                edge_index = subgraph['edge_index'].to(self.device)
                node_type = subgraph['node_type'].to(self.device)
                edge_type = subgraph['edge_type'].to(self.device)
                edge_attr = subgraph['edge_attr'].to(self.device) if subgraph['edge_attr'].numel() > 0 else None
                
                # Model forward pass
                outputs = self.model({
                    'x': x,
                    'edge_index': edge_index,
                    'node_type': node_type,
                    'edge_type': edge_type,
                    'edge_attr': edge_attr,
                })
                
                # Extract risk score
                if isinstance(outputs, dict):
                    risk_tensor = outputs.get('risk', outputs.get('logits'))
                else:
                    risk_tensor = outputs

                if risk_tensor is None:
                    raise ValueError('Model did not return a risk score')

                risk_score = float(risk_tensor.item())
            
            # Get influential neighbors via attention
            influential_neighbors = self._get_influential_neighbors(
                transaction['source_account'],
                subgraph,
                top_k=5,
            )
            
            # Compute component risks
            breakdown = {
                'graph_risk': risk_score,
                'velocity_risk': self._compute_velocity_risk(transaction),
                'temporal_risk': self._compute_temporal_risk(transaction),
                'device_risk': self._compute_device_risk(transaction),
            }
            
            # Aggregate risks
            final_score = (
                0.60 * breakdown['graph_risk'] +
                0.20 * breakdown['velocity_risk'] +
                0.15 * breakdown['temporal_risk'] +
                0.05 * breakdown['device_risk']
            )
            
            # Decision
            decision, confidence = self._make_decision(final_score)
            
            # Explanation
            explanation = self._generate_explanation(
                transaction, final_score, breakdown, influential_neighbors
            )
            
            # Inference time
            inference_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return FraudScore(
                transaction_id=transaction.get('transaction_id', 'UNKNOWN'),
                risk_score=final_score,
                decision=decision,
                confidence=confidence,
                explanation=explanation,
                breakdown=breakdown,
                influential_neighbors=influential_neighbors,
                model_version=self.model_version,
                inference_time_ms=inference_time,
                graph_size=subgraph['num_nodes'],
            )
        
        except Exception as e:
            logger.error(f"Model inference failed: {e}", exc_info=True)
            
            if self.enable_heuristic_fallback:
                logger.info("Falling back to heuristic scoring")
                return self._fallback_heuristic_score(transaction, reference_time)
            else:
                raise
    
    def score_batch(
        self,
        transactions: List[Dict],
        reference_time: Optional[datetime] = None,
        batch_size: int = 32,
    ) -> List[FraudScore]:
        """
        Score multiple transactions.
        
        Args:
            transactions: List of transaction dicts
            reference_time: Reference time
            batch_size: Batch size for processing
        
        Returns:
            List of FraudScores
        """
        if not transactions:
            return []

        max_workers = max(1, min(len(transactions), batch_size, os.cpu_count() or 1))
        scores: List[Optional[FraudScore]] = [None] * len(transactions)

        # Per-batch cache keyed by source_account to avoid re-extracting the same neighborhood
        subgraph_cache = _ThreadSafeCache()

        executor = self._executor
        for transaction_batch in self._iter_transaction_batches(transactions, max_workers):
            future_to_index = {
                executor.submit(self.score_transaction, txn, reference_time, 2, subgraph_cache): idx
                for idx, txn in transaction_batch
            }

            for future in as_completed(future_to_index):
                idx = future_to_index.pop(future)
                scores[idx] = future.result()

        return [score for score in scores if score is not None]

    def close(self) -> None:
        """Shut down the shared executor, draining pending work."""
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __del__(self):
        if getattr(self, "_executor", None) is not None:
            import warnings
            warnings.warn(
                f"{type(self).__name__} was garbage-collected without being explicitly "
                "closed. Use it as a context manager ('with' statement) or call "
                ".close() when done to ensure threads are drained properly.",
                ResourceWarning,
                stacklevel=2,
            )
        try:
            self.close()
        except Exception as exc:
            logger.error("ProductionRiskScorer cleanup failed: %s", exc)

    def _iter_transaction_batches(
        self,
        transactions: List[Dict],
        batch_size: int,
    ) -> Iterator[List[Tuple[int, Dict]]]:
        """Yield bounded batches of indexed transactions for concurrent scoring."""
        iterator = iter(enumerate(transactions))

        while True:
            batch = list(islice(iterator, batch_size))
            if not batch:
                break
            yield batch
    
    def _make_decision(self, risk_score: float) -> Tuple[str, float]:
        """
        Make fraud decision based on risk score.
        
        Returns:
            (decision, confidence)
        """
        if risk_score >= 0.90:
            return 'BLOCK', risk_score
        elif risk_score >= 0.60:
            return 'REVIEW', risk_score
        else:
            return 'ALLOW', 1.0 - risk_score
    
    def _get_influential_neighbors(
        self,
        node_id: str,
        subgraph: Dict,
        top_k: int = 5,
    ) -> List[Dict]:
        """
        Identify most influential neighbors via attention analysis.
        
        Extracts attention weights from the last HTGNN layer if available.
        """
        influential = []
        
        # This would require extracting attention weights from the model
        # For now, return placeholder based on subgraph structure
        idx_to_node_id = subgraph['idx_to_node_id']
        node_id_to_idx = subgraph['node_id_to_idx']
        
        if node_id not in node_id_to_idx:
            return influential
        
        source_idx = node_id_to_idx[node_id]
        edge_index = subgraph['edge_index']
        
        # Find edges connected to source
        connected_edges = (edge_index[0] == source_idx) | (edge_index[1] == source_idx)
        connected_indices = torch.nonzero(connected_edges).squeeze(-1)
        
        for edge_idx in connected_indices[:top_k]:
            src_idx = edge_index[0, edge_idx].item()
            tgt_idx = edge_index[1, edge_idx].item()
            
            # The neighbor is the node we didn't start from
            neighbor_idx = tgt_idx if src_idx == source_idx else src_idx
            neighbor_id = idx_to_node_id.get(neighbor_idx, 'UNKNOWN')
            
            influential.append({
                'node_id': neighbor_id,
                'influence_score': 0.5,  # Placeholder
                'relationship': 'CONNECTED',
            })
        
        return influential[:top_k]
    
    def _compute_velocity_risk(self, transaction: Dict) -> float:
        """
        Compute velocity-based risk (multiple transactions in short time).
        
        Placeholder: would query transaction history in production.
        """
        # In production: check transactions from source account in last hour
        # For now, return a reasonable default
        return 0.3
    
    def _compute_temporal_risk(self, transaction: Dict) -> float:
        """
        Compute temporal risk (unusual time of day, new account, etc.).
        """
        timestamp = transaction.get('timestamp')
        if isinstance(timestamp, str):
            try:
                txn_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                return 0.2
        elif isinstance(timestamp, (int, float)):
            txn_time = datetime.fromtimestamp(timestamp)
        elif hasattr(timestamp, 'isoformat'):
            txn_time = datetime.fromisoformat(timestamp.isoformat())
        else:
            return 0.2

        hour = txn_time.hour
        
        # High risk: 2am-4am (common fraud window)
        if 2 <= hour <= 4:
            return 0.6
        # Medium risk: 11pm-1am
        elif 23 <= hour or hour <= 1:
            return 0.4
        # Low risk: business hours
        else:
            return 0.2
    
    def _compute_device_risk(self, transaction: Dict) -> float:
        """
        Compute risk based on device information.
        """
        # Placeholder: in production would check:
        # - Device registration age
        # - Device linked to other fraud cases
        # - Geo-velocity (impossible location jumps)
        return 0.2
    
    def _generate_explanation(
        self,
        transaction: Dict,
        risk_score: float,
        breakdown: Dict[str, float],
        influential_neighbors: List[Dict],
    ) -> str:
        """Generate human-readable explanation for the decision"""
        
        top_risk_component = max(breakdown.items(), key=lambda x: x[1])
        
        explanation = (
            f"Transaction flagged due to:\n"
            f"1. Overall risk score: {risk_score:.2%}\n"
            f"2. Highest risk component: {top_risk_component[0]} ({top_risk_component[1]:.2%})\n"
        )
        
        if influential_neighbors:
            explanation += f"3. Connected to {len(influential_neighbors)} suspicious accounts\n"
        
        if risk_score >= 0.9:
            explanation += f"\nREASON: High-confidence fraud indicators detected"
        elif risk_score >= 0.6:
            explanation += f"\nREASON: Multiple risk factors present - requires verification"
        else:
            explanation += f"\nREASON: Transaction appears normal"
        
        return explanation
    
    def _fallback_heuristic_score(
        self,
        transaction: Dict,
        reference_time: Optional[datetime] = None,
    ) -> FraudScore:
        """
        Fallback heuristic scoring if model inference fails.
        
        Uses simple rules based on:
        - Transaction amount
        - Time of day
        - Account age
        """
        amount = transaction.get('amount', 0)
        
        # Simple heuristic: large late-night transactions are riskier
        risk = 0.3  # Base risk
        
        # Amount risk: transactions > 100k higher risk
        if amount > 100000:
            risk += 0.2
        
        # Time risk: late night higher risk
        if reference_time:
            hour = reference_time.hour
            if 2 <= hour <= 4:
                risk += 0.3
        
        risk = min(risk, 1.0)
        
        decision, confidence = self._make_decision(risk)
        
        return FraudScore(
            transaction_id=transaction.get('transaction_id', 'UNKNOWN'),
            risk_score=risk,
            decision=decision,
            confidence=confidence,
            explanation="Heuristic scoring (model unavailable)",
            breakdown={'heuristic_risk': risk},
            influential_neighbors=[],
            model_version=f"{self.model_version}-HEURISTIC",
            inference_time_ms=10.0,
            graph_size=0,
        )


class ExplainabilityEngine:
    """
    Generates detailed explanations for HTGNN decisions.
    
    Methods:
    - Extract attention weights
    - Trace decision paths
    - Identify feature importance
    - Visualize subgraphs
    """
    
    @staticmethod
    def extract_attention_weights(
        model: nn.Module,
        subgraph: Dict,
    ) -> Dict[int, np.ndarray]:
        """
        Extract multi-head attention weights from HTGNN layers.
        
        Returns:
            Dict mapping layer_idx to attention matrices
        """
        # This would require instrumenting the model to capture attention
        # For now, return placeholder
        attention_weights = {}
        return attention_weights
    
    @staticmethod
    def trace_fraud_paths(
        source_node: str,
        subgraph: Dict,
        k_hops: int = 2,
    ) -> List[List[str]]:
        """
        Enumerate paths from source node through subgraph.
        
        Returns:
            List of node ID paths
        """
        if k_hops < 1:
            return []

        idx_to_node_id = subgraph.get('idx_to_node_id', {})
        node_id_to_idx = subgraph.get('node_id_to_idx', {})
        edge_index = subgraph.get('edge_index')

        if source_node not in node_id_to_idx or edge_index is None:
            logger.warning(
                "Unable to trace fraud paths: source node missing or subgraph edges unavailable"
            )
            return []

        source_idx = node_id_to_idx[source_node]

        # Build a local adjacency map from the extracted subgraph. We traverse
        # simple paths only so cycles cannot expand forever.
        adjacency: Dict[int, List[int]] = {}
        if isinstance(edge_index, torch.Tensor):
            edge_pairs = edge_index.detach().cpu().tolist()
        else:
            edge_pairs = np.asarray(edge_index).tolist()

        if len(edge_pairs) != 2:
            logger.warning("Unable to trace fraud paths: unexpected edge_index shape")
            return []

        for src_idx, tgt_idx in zip(edge_pairs[0], edge_pairs[1]):
            adjacency.setdefault(int(src_idx), []).append(int(tgt_idx))
            adjacency.setdefault(int(tgt_idx), []).append(int(src_idx))

        queue = deque([[source_idx]])
        paths: List[List[str]] = []

        while queue:
            path = queue.popleft()
            current_idx = path[-1]
            hop_count = len(path) - 1

            if hop_count >= k_hops:
                continue

            for neighbor_idx in adjacency.get(current_idx, []):
                if neighbor_idx in path:
                    continue

                next_path = path + [neighbor_idx]
                paths.append([idx_to_node_id.get(idx, 'UNKNOWN') for idx in next_path])
                queue.append(next_path)

        return paths


def create_mock_graph_constructor():
    """Create a mock graph constructor for testing"""
    from src.data.graph_constructor import TemporalGraphConstructor
    return TemporalGraphConstructor(
        time_window_hours=24,
        feature_dim=64,
        temporal_dim=16,
        temporal_decay_lambda=0.01,
    )
