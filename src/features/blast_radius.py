"""
Blast Radius Analytics — AegisGraph Sentinel 2.0
=================================================

Implements iterative contagion-score propagation across a fraud graph starting
from a single flagged vertex.  Results are bucketed into risk tiers so that
consuming services can immediately lock / quarantine affected nodes.

Algorithm
---------
For every reachable neighbor *v* of a flagged source node *s*:

    Sc(v) = Σ  weight(u→v) / depth(u→v)²

where the sum runs over every directed edge that arrives at *v* during a
bounded-depth BFS.  A ``visited`` set prevents infinite loops on cyclic
sub-graphs (e.g. round-robin fraud rings).

Risk Tiers
----------
+-----------+-------------------+
| Tier      | Contagion Score   |
+===========+===================+
| CRITICAL  | Sc ≥ 0.70         |
| HIGH      | 0.35 ≤ Sc < 0.70  |
| SUSPICIOUS| 0.10 ≤ Sc < 0.35  |
+-----------+-------------------+

Nodes with Sc < 0.10 are below the detection threshold and are *not* included
in the response payload.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# NetworkX is a hard dependency of the project (already in requirements.txt).
import networkx as nx


# ---------------------------------------------------------------------------
# Tier thresholds
# ---------------------------------------------------------------------------

TIER_CRITICAL: float = 0.70
TIER_HIGH: float = 0.35
TIER_SUSPICIOUS: float = 0.10

# Maximum absolute cap on max_depth accepted by the analyser (the API layer
# may impose a tighter cap via Pydantic).
HARD_MAX_DEPTH: int = 10


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ContagionResult:
    """Per-node contagion result produced by BlastRadiusAnalyzer."""

    node_id: str
    contagion_score: float
    risk_tier: str          # "CRITICAL" | "HIGH" | "SUSPICIOUS"
    depth: int              # shortest-path hop distance from origin


@dataclass
class BlastRadiusReport:
    """Aggregated report returned by BlastRadiusAnalyzer.compute()."""

    source_node: str
    max_depth: int
    total_nodes_evaluated: int
    critical: List[ContagionResult] = field(default_factory=list)
    high: List[ContagionResult] = field(default_factory=list)
    suspicious: List[ContagionResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core analyser
# ---------------------------------------------------------------------------


class BlastRadiusAnalyzer:
    """
    Graph traversal engine that calculates contagion scores and groups
    discovered nodes into risk tiers.

    Thread-safety
    ~~~~~~~~~~~~~
    All state is local to ``compute()``; the instance itself is stateless and
    can be shared across requests.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute(
        self,
        source_node: str,
        graph: nx.DiGraph,
        max_depth: int = 3,
    ) -> BlastRadiusReport:
        """
        Perform a bounded BFS from *source_node* and return a
        :class:`BlastRadiusReport`.

        Parameters
        ----------
        source_node:
            The flagged vertex to start from.
        graph:
            A **directed** NetworkX graph (``DiGraph`` or ``MultiDiGraph``).
            The algorithm propagates contagion *along* the direction of fund
            transfers (A → B means B is downstream of A).  Passing an
            undirected graph would traverse edges in both directions, causing
            innocent upstream senders to be scored as fraud targets — which
            is semantically incorrect and raises ``TypeError``.
        max_depth:
            Maximum hop count.  Capped internally at ``HARD_MAX_DEPTH``.

        Returns
        -------
        BlastRadiusReport
            Contains categorised lists of :class:`ContagionResult` objects.

        Raises
        ------
        TypeError
            If *graph* is not a directed graph (i.e. ``graph.is_directed()``
            returns ``False``).
        ValueError
            If *source_node* is not present in *graph*.
        """
        if not graph.is_directed():
            raise TypeError(
                "BlastRadiusAnalyzer.compute() requires a directed graph "
                "(nx.DiGraph or nx.MultiDiGraph). An undirected graph would "
                "traverse edges in both directions, scoring innocent upstream "
                "senders as fraud contagion targets."
            )

        max_depth = min(max_depth, HARD_MAX_DEPTH)

        if hasattr(graph, "is_active") and graph.is_active:
            if hasattr(graph, "compute_blast_radius") and callable(graph.compute_blast_radius):
                return graph.compute_blast_radius(source_node, max_depth)

        if source_node not in graph:
            raise ValueError(
                f"Source node {source_node!r} not found in graph "
                f"({graph.number_of_nodes()} nodes total)."
            )

        # scores[node] accumulates Sc contributions from all arriving edges.
        scores: Dict[str, float] = {}
        # shortest[node] tracks the first (shortest) depth at which a node
        # was reached — used for display purposes only.
        shortest_depth: Dict[str, int] = {}
        # visited prevents re-expanding a node via a longer path, which also
        # prevents infinite loops in cyclic graphs.
        visited: set = {source_node}

        # BFS queue stores (current_node, depth)
        queue: deque = deque([(source_node, 0)])

        while queue:
            current_node, current_depth = queue.popleft()

            if current_depth >= max_depth:
                # Reached the depth limit — do not expand further.
                continue

            next_depth = current_depth + 1

            for neighbor in self._iter_successors(graph, current_node):
                if neighbor == source_node:
                    # Never score the origin node itself.
                    continue

                edge_weight = self._edge_weight(graph, current_node, neighbor)
                contribution = edge_weight / (next_depth ** 2)

                # Accumulate score
                scores[neighbor] = scores.get(neighbor, 0.0) + contribution

                # Record shortest depth (first time we see this node)
                if neighbor not in shortest_depth:
                    shortest_depth[neighbor] = next_depth

                # Only enqueue for further expansion if not visited yet.
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, next_depth))

        # ------------------------------------------------------------------
        # Build report
        # ------------------------------------------------------------------
        critical: List[ContagionResult] = []
        high: List[ContagionResult] = []
        suspicious: List[ContagionResult] = []

        for node_id, score in scores.items():
            tier = self._classify(score)
            if tier is None:
                continue  # Below detection threshold

            result = ContagionResult(
                node_id=node_id,
                contagion_score=round(score, 6),
                risk_tier=tier,
                depth=shortest_depth.get(node_id, -1),
            )

            if tier == "CRITICAL":
                critical.append(result)
            elif tier == "HIGH":
                high.append(result)
            else:
                suspicious.append(result)

        # Sort each tier by score descending for consumer convenience.
        for bucket in (critical, high, suspicious):
            bucket.sort(key=lambda r: r.contagion_score, reverse=True)

        return BlastRadiusReport(
            source_node=source_node,
            max_depth=max_depth,
            total_nodes_evaluated=len(scores),
            critical=critical,
            high=high,
            suspicious=suspicious,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_successors(graph: nx.DiGraph, node: str):
        """Yield the direct successors of *node* in a directed graph."""
        yield from graph.successors(node)

    @staticmethod
    def _edge_weight(graph: nx.Graph, u: str, v: str) -> float:
        """
        Extract a scalar edge weight, handling MultiGraph edge bundles.
        Returns ``1.0`` when no weight is stored.
        """
        try:
            edge_data = graph[u][v]
        except KeyError:
            return 1.0

        # MultiGraph / MultiDiGraph: edge_data is a dict-of-dicts keyed by
        # edge index.  Use the weight of the first parallel edge.
        if isinstance(edge_data, dict):
            # Check if it looks like a MultiGraph bundle (values are dicts)
            first_value = next(iter(edge_data.values()), None)
            if isinstance(first_value, dict):
                # MultiGraph — extract weight from the first edge
                return float(first_value.get("weight", 1.0))
            # Regular DiGraph / Graph edge_data dict
            return float(edge_data.get("weight", 1.0))

        return 1.0

    @staticmethod
    def _classify(score: float) -> Optional[str]:
        """Map a contagion score to a risk tier string, or None if below threshold."""
        if score >= TIER_CRITICAL:
            return "CRITICAL"
        if score >= TIER_HIGH:
            return "HIGH"
        if score >= TIER_SUSPICIOUS:
            return "SUSPICIOUS"
        return None
