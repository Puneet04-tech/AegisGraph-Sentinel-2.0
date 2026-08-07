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
from collections import deque, OrderedDict
from threading import Lock
from typing import Any, Dict, Iterator, List, Optional, Tuple
from dataclasses import dataclass, asdict

from .timestamps import hour_in_zone
from datetime import datetime, timezone, tzinfo
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
    top_relationships: List[Dict]
    high_risk_nodes: List[str]
    attention_summary: str
    model_version: str
    inference_time_ms: float
    graph_size: int  # Number of nodes in subgraph
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the fraud score to a dictionary."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Serialize the fraud score to a JSON string."""
        return json.dumps(self.to_dict(), default=str)


class _ThreadSafeCache:
    """Thread-safe LRU cache for concurrent subgraph caching.

    Bounded by maxsize to prevent unbounded tensor memory accumulation
    within a single batch when all source accounts are distinct.
    """

    def __init__(self, maxsize: int = 256):
        self._data: OrderedDict[Any, Dict] = OrderedDict()
        self._lock = Lock()
        self._maxsize = maxsize

    def get(self, key: Any) -> Optional[Dict]:
        """Retrieve a cached value and move it to the end (most recently used)."""
        with self._lock:
            if key not in self._data:
                return None
            self._data.move_to_end(key)
            return self._data[key]

    def set(self, key: Any, value: Dict) -> None:
        """Store a value in the cache, evicting the least recently used item if at capacity."""
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = value
            if len(self._data) > self._maxsize:
                self._data.popitem(last=False)


class ProductionRiskScorer:
    """
    Production-grade fraud scorer using HTGNN.

    Decision Logic:
    - score ≥ 0.9: BLOCK (high confidence fraud)
    - 0.6 ≤ score < 0.9: REVIEW (needs analyst)
    - score < 0.6: ALLOW (normal transaction)

    UNPARSEABLE_TEMPORAL_RISK: Risk returned when a timestamp cannot be
    interpreted at all -- the same neutral value the previous implementation
    used, kept as a named constant so it is not a bare literal in two branches.

    Lifecycle:
    Use as a context manager or call `.close()` explicitly when done.
    Failing to do so will emit a ResourceWarning and may leave threads
    alive past the object's logical lifetime::

        with ProductionRiskScorer(model, graph_constructor) as scorer:
            result = scorer.score_transaction(request)
    """
    
    #: Returned when a timestamp cannot be interpreted at all.
    UNPARSEABLE_TEMPORAL_RISK = 0.2

    def __init__(
        self,
        model: nn.Module,
        graph_constructor,
        device: str = 'cpu',
        model_version: str = '2.0.0',
        enable_heuristic_fallback: bool = True,
        temporal_reference_zone: Optional[tzinfo] = None,
    ):
        """
        Args:
            model: Trained HTGNN model
            graph_constructor: TemporalGraphConstructor instance
            device: 'cuda' or 'cpu'
            model_version: Version string for logging
            enable_heuristic_fallback: Fall back if model fails
            temporal_reference_zone: Timezone the fraud-window hours are
                evaluated in; defaults to UTC so results are host-independent
        """
        self.model = model
        self.model.eval()
        self.graph_constructor = graph_constructor
        self.device = device
        self.model_version = model_version
        self.enable_heuristic_fallback = enable_heuristic_fallback
        
        self._executor = ThreadPoolExecutor(max_workers=os.cpu_count() or 1)

        # Explicit rather than implicit: the hour a scoring rule sees must not
        # depend on the host's TZ environment variable.
        self.temporal_reference_zone = temporal_reference_zone or timezone.utc

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
        start_time = datetime.now(timezone.utc)
        
        try:
            # Extract subgraph around source account (cached per batch with temporal and hop key)
            source = transaction['source_account']
            cache_key = (source, reference_time, k_hops)
            subgraph = _subgraph_cache.get(cache_key) if _subgraph_cache is not None else None
            if subgraph is None:
                subgraph = self.graph_constructor.get_subgraph_around_node(
                    node_id=source,
                    k_hops=k_hops,
                    reference_time=reference_time,
                )
                if _subgraph_cache is not None:
                    _subgraph_cache.set(cache_key, subgraph)
            
            # Clone tensors to prevent thread data races when executing concurrent workers
            if isinstance(subgraph, dict):
                subgraph = {
                    k: (v.clone() if isinstance(v, torch.Tensor) else v)
                    for k, v in subgraph.items()
                }
            
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
                attention_weights = None
                attention_edge_index = None

                if isinstance(outputs, dict):
                    attention_weights = outputs.get("attention_weights")
                    attention_edge_index = outputs.get("attention_edge_index")
                
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
                attention_weights=attention_weights,
                attention_edge_index=attention_edge_index,
            )
            top_relationships = self._extract_top_relationships(
                subgraph,
                attention_weights,
                attention_edge_index,
                top_k=5,
            )

            high_risk_nodes = self._identify_high_risk_nodes(top_relationships)
            attention_summary = self._generate_attention_summary(top_relationships)
            
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
            inference_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            return FraudScore(
                transaction_id=transaction.get('transaction_id', 'UNKNOWN'),
                risk_score=final_score,
                decision=decision,
                confidence=confidence,
                explanation=explanation,
                breakdown=breakdown,
                influential_neighbors=influential_neighbors,
                top_relationships=top_relationships,
                high_risk_nodes=high_risk_nodes,
                attention_summary=attention_summary,
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

    def __enter__(self) -> "ProductionRiskScorer":
        return self

    def __exit__(self, *exc: object) -> bool:
        self.close()
        return False

    def __del__(self) -> None:
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
        if risk_score is None:
            return "ALLOW", 0.0
        risk_score = max(0.0, min(1.0, risk_score))
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
        attention_weights=None,
        attention_edge_index=None,
    ) -> List[Dict]:
        """
        Identify most influential neighbors via attention analysis.

        Ranks by the model's own attention weights when the HTGNN exposes
        them, and by a structural fallback otherwise. The relationship label
        is the real edge type rather than a constant.

        This previously attached ``'influence_score': 0.5`` to every neighbour
        and returned them in edge-index order, so any sort by influence was a
        no-op and the set an analyst saw was determined by internal tensor
        ordering rather than by anything about the graph.
        """
        node_id_to_idx = subgraph.get('node_id_to_idx') or {}
        idx_to_node_id = subgraph.get('idx_to_node_id') or {}

        if node_id not in node_id_to_idx:
            return []

        source_idx = node_id_to_idx[node_id]
        edge_index = subgraph.get('edge_index')
        if edge_index is None or edge_index.numel() == 0:
            return []

        attention_by_pair = self._attention_by_pair(
            attention_weights, attention_edge_index
        )

        connected_edges = (edge_index[0] == source_idx) | (edge_index[1] == source_idx)
        connected_indices = torch.nonzero(connected_edges).squeeze(-1)

        # Best score per neighbour: a pair joined by several edges is one
        # neighbour, ranked by its strongest connection.
        best: Dict[int, Dict] = {}

        for edge_idx in connected_indices.tolist():
            src_idx = int(edge_index[0, edge_idx].item())
            tgt_idx = int(edge_index[1, edge_idx].item())

            # A self-loop has no neighbour to report.
            if src_idx == tgt_idx:
                continue

            neighbor_idx = tgt_idx if src_idx == source_idx else src_idx
            score = attention_by_pair.get((src_idx, tgt_idx))
            if score is None:
                score = attention_by_pair.get((tgt_idx, src_idx))
            if score is None:
                score = self._structural_influence(subgraph, edge_idx, neighbor_idx)

            existing = best.get(neighbor_idx)
            if existing is None or score > existing['influence_score']:
                best[neighbor_idx] = {
                    'node_id': idx_to_node_id.get(neighbor_idx, 'UNKNOWN'),
                    'influence_score': round(float(score), 4),
                    'relationship': self._edge_type_label(subgraph, edge_idx),
                }

        # Descending by influence, with node_id breaking ties so repeated
        # scoring of an unchanged subgraph returns a stable ordering.
        ranked = sorted(
            best.values(),
            key=lambda item: (-item['influence_score'], item['node_id']),
        )
        return ranked[:top_k]

    @staticmethod
    def _attention_by_pair(attention_weights, attention_edge_index) -> Dict:
        """Map each attended (src, dst) pair to its normalised attention score."""
        if attention_weights is None or attention_edge_index is None:
            return {}
        if attention_edge_index.numel() == 0 or attention_weights.numel() == 0:
            return {}

        scores = (
            attention_weights.mean(dim=-1)
            if attention_weights.dim() > 1
            else attention_weights
        )

        # Normalised so influence is comparable across transactions, whose
        # raw attention magnitudes depend on subgraph size.
        peak = float(scores.max().item()) if scores.numel() else 0.0
        if peak <= 0:
            return {}

        pair_scores: Dict = {}
        edge_count = min(scores.numel(), attention_edge_index.shape[1])
        for position in range(edge_count):
            src = int(attention_edge_index[0, position].item())
            dst = int(attention_edge_index[1, position].item())
            value = float(scores[position].item()) / peak
            key = (src, dst)
            # Several attention heads or layers may touch one pair; keep the
            # strongest.
            if value > pair_scores.get(key, 0.0):
                pair_scores[key] = value
        return pair_scores

    @staticmethod
    def _structural_influence(subgraph: Dict, edge_idx: int, neighbor_idx: int) -> float:
        """Fallback influence when the model exposes no attention weights.

        Combines the edge's own weight with the neighbour's risk, both of
        which are defensible proxies for how much a connection matters.
        """
        score = 0.5
        edge_attr = subgraph.get('edge_attr')
        if edge_attr is not None and edge_attr.numel() > 0 and edge_idx < edge_attr.shape[0]:
            row = edge_attr[edge_idx]
            magnitude = float(row.abs().mean().item()) if row.numel() else 0.0
            # Squashed into (0, 1) so an unbounded feature cannot dominate.
            score = magnitude / (1.0 + magnitude)

        node_risk = subgraph.get('node_risk')
        if node_risk is not None and neighbor_idx < len(node_risk):
            try:
                risk = float(node_risk[neighbor_idx])
            except (TypeError, ValueError):
                risk = 0.0
            score = max(score, min(1.0, max(0.0, risk)))

        return min(1.0, max(0.0, score))

    @staticmethod
    def _edge_type_label(subgraph: Dict, edge_idx: int) -> str:
        """Real edge type for an edge, replacing the constant 'CONNECTED'."""
        edge_type = subgraph.get('edge_type')
        if edge_type is None or edge_idx >= edge_type.shape[0]:
            return 'CONNECTED'

        try:
            type_id = int(edge_type[edge_idx].item())
        except (TypeError, ValueError, RuntimeError):
            return 'CONNECTED'

        names = subgraph.get('edge_type_names')
        if names and 0 <= type_id < len(names):
            return str(names[type_id])
        return f'EDGE_TYPE_{type_id}'

    def _extract_top_relationships(
        self,
        subgraph: Dict,
        attention_weights,
        attention_edge_index,
        top_k: int = 5,
    ) -> List[Dict]:
        """
        Extract highest-attention graph relationships.
        """

        if (
            attention_weights is None
            or attention_edge_index is None
        ):
            return []

        idx_to_node_id = subgraph["idx_to_node_id"]

        # Multi-head attention -> average heads
        if attention_weights.dim() > 1:
            scores = attention_weights.mean(dim=-1)
        else:
            scores = attention_weights

        top_indices = torch.argsort(
            scores,
            descending=True,
        )[:top_k]

        relationships = []

        for edge_pos in top_indices:

            edge_pos = edge_pos.item()

            src_idx = attention_edge_index[0, edge_pos].item()
            dst_idx = attention_edge_index[1, edge_pos].item()

            relationships.append(
                {
                    "source_node": idx_to_node_id.get(
                        src_idx,
                        "UNKNOWN",
                    ),
                    "target_node": idx_to_node_id.get(
                        dst_idx,
                        "UNKNOWN",
                    ),
                    "attention_score": round(
                        float(scores[edge_pos]),
                        4,
                    ),
                }
            )

        return relationships
    
    def _identify_high_risk_nodes(
        self,
        top_relationships: List[Dict],
    ) -> List[str]:

        nodes = []

        for relationship in top_relationships:

            nodes.append(
                relationship["source_node"]
            )

            nodes.append(
                relationship["target_node"]
            )

        return list(dict.fromkeys(nodes))[:5]
    
    def _generate_attention_summary(
        self,
        top_relationships: List[Dict],
    ) -> str:

        if not top_relationships:
            return "No high-attention graph relationships identified."

        lines = []

        for relationship in top_relationships:

            lines.append(
                f"{relationship['source_node']} -> "
                f"{relationship['target_node']} "
                f"(Attention Score: "
                f"{relationship['attention_score']:.2f})"
            )

        return "\n".join(lines)
    
    def _compute_velocity_risk(self, transaction: Dict) -> float:
        """
        Compute velocity-based risk (multiple transactions in short time).

        Scored against the source account's recent activity, then the
        transaction is recorded so subsequent scoring sees it. Scoring happens
        before recording so a transaction never contributes to its own
        velocity.

        This previously returned the constant 0.3, which meant a burst of
        transfers and a single monthly payment contributed identically.
        """
        account_id = (
            transaction.get('source_account')
            or transaction.get('from_account')
            or transaction.get('account_id')
        )
        if not account_id:
            # Nothing to attribute the activity to; fall back to the
            # calculator's documented cold-start value rather than guessing.
            return self.velocity_calculator.cold_start_risk

        return self.velocity_calculator.score_and_record(
            account_id=str(account_id),
            amount=transaction.get('amount', 0.0),
            timestamp=transaction.get('timestamp'),
            transaction_id=transaction.get('transaction_id'),
        )
    
    def _compute_temporal_risk(self, transaction: Dict) -> float:
        """
        Compute temporal risk (unusual time of day, new account, etc.).

        The hour is evaluated in an explicit reference timezone (UTC by
        default), not the host's. Numeric timestamps previously went through
        `datetime.fromtimestamp(value)` with no tz argument, which returns
        naive local time -- so the same transaction scored 0.6 or 0.2 depending
        purely on which region a worker ran in, and moving a deployment
        silently re-classified its entire traffic profile.
        """
        hour = hour_in_zone(
            transaction.get('timestamp'), self.temporal_reference_zone
        )
        if hour is None:
            return self.UNPARSEABLE_TEMPORAL_RISK

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
            top_relationships=[],
            high_risk_nodes=[],
            attention_summary="No graph investigation data available.",
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
        Extract multi-head attention weights from HTGAT layers.

        Returns:
            Dict mapping layer index to attention weights.
        """
        try:
            model.eval()

            with torch.no_grad():

                outputs = model(
                    {
                        'x': subgraph['x'],
                        'edge_index': subgraph['edge_index'],
                        'node_type': subgraph['node_type'],
                        'edge_type': subgraph['edge_type'],
                        'edge_attr': subgraph['edge_attr'],
                    },
                    return_attention_weights=True,
                )

            attention = outputs.get('attention_weights')

            if attention is None:
                return {}

            return {
                0: attention.detach().cpu().numpy()
            }

        except Exception as exc:
            logger.error(
                "Failed to extract attention weights: %s",
                exc,
                exc_info=True,
            )
            return {}
    
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
