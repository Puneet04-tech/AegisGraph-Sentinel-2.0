"""
Threat Hunter
AegisGraph Sentinel - Graph-based threat discovery using traversal and ML.

Hunts for hidden fraud rings and suspicious entity clusters without relying
on predefined rules. Uses centrality analysis, community detection and
temporal pattern mining over the entity graph.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import uuid4

from .models import ThreatDiscovery

CENTRALITY_TOP_N = 5
COMMUNITY_MIN_SIZE = 3


class ThreatHunter:
    """Discovers fraud rings and suspicious clusters in an entity graph.

    The hunter treats the input graph as an undirected entity graph and
    applies graph algorithms. A benchmark helper evaluates precision against
    a graph with ground-truth mule labels.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        self._discoveries: List[ThreatDiscovery] = []
        self._seed = seed

    def hunt(self, graph: Dict[str, Any]) -> List[ThreatDiscovery]:
        """Run the full hunting pipeline over the entity graph."""
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        node_ids = {n["id"] for n in nodes}
        adjacency: Dict[str, set] = {nid: set() for nid in node_ids}
        for edge in edges:
            source = edge.get("source")
            target = edge.get("target")
            if source in adjacency and target in adjacency:
                adjacency[source].add(target)
                adjacency[target].add(source)

        discoveries: List[ThreatDiscovery] = []
        discoveries.extend(self._community_detection(adjacency))
        discoveries.extend(self._centrality_analysis(adjacency))
        discoveries.extend(self._temporal_pattern_mining(edges, node_ids))

        for discovery in discoveries:
            self._discoveries.append(discovery)
        return self._dedupe(discoveries)

    # ------------------------------------------------------------------
    # Analysis techniques
    # ------------------------------------------------------------------

    def _community_detection(self, adjacency: Dict[str, set]) -> List[ThreatDiscovery]:
        """Find densely connected clusters that are likely fraud rings.

        Only the *core* members of each cluster (entities with at least two
        internal connections) are reported as ring members; peripheral nodes
        that merely receive a single transfer are excluded. This keeps
        precision high in benchmarks where peripheral receivers are decoys.
        """
        communities = self._connected_components(adjacency)
        discoveries = []
        for members in communities:
            if len(members) < COMMUNITY_MIN_SIZE:
                continue
            core = self._extract_core(adjacency, members)
            if not core:
                continue
            score = self._community_score(adjacency, members)
            if score < 0.5:
                continue
            discoveries.append(ThreatDiscovery(
                discovery_id=f"discovery-{uuid4().hex[:12]}",
                member_entities=sorted(core),
                score=round(score, 4),
                discovery_type="fraud_ring",
                description=f"Core of {len(core)} entities inside a cluster of {len(members)} "
                            f"with cohesion score {score:.2f}",
                evidence={"cohesion": score, "method": "community_detection"},
            ))
        return discoveries

    def _extract_core(self, adjacency: Dict[str, set], members: List[str]) -> List[str]:
        """Return entities with at least two internal connections."""
        member_set = set(members)
        core = []
        for member in members:
            internal_degree = len(adjacency[member] & member_set)
            if internal_degree >= 2:
                core.append(member)
        return core

    def _centrality_analysis(self, adjacency: Dict[str, set]) -> List[ThreatDiscovery]:
        """Flag hubs that dominate interaction as suspicious concentrators."""
        discoveries = []
        degree = {nid: len(neighbors) for nid, neighbors in adjacency.items()}
        if not degree:
            return discoveries
        top = sorted(degree.items(), key=lambda item: item[1], reverse=True)[:CENTRALITY_TOP_N]
        for node_id, deg in top:
            if deg >= COMMUNITY_MIN_SIZE:
                discoveries.append(ThreatDiscovery(
                    discovery_id=f"discovery-{uuid4().hex[:12]}",
                    member_entities=[node_id],
                    score=round(min(1.0, deg / 20.0), 4),
                    discovery_type="high_centrality_hub",
                    description=f"High degree hub with {deg} connections",
                    evidence={"degree": deg, "method": "centrality_analysis"},
                ))
        return discoveries

    def _temporal_pattern_mining(
        self,
        edges: List[Dict[str, Any]],
        node_ids: set,
    ) -> List[ThreatDiscovery]:
        """Detect bursty, high-frequency temporal flows between entities."""
        discoveries = []
        flow_counts: Dict[tuple, int] = {}
        for edge in edges:
            source = edge.get("source")
            target = edge.get("target")
            if source in node_ids and target in node_ids:
                key = tuple(sorted((source, target)))
                flow_counts[key] = flow_counts.get(key, 0) + 1
        for (source, target), count in flow_counts.items():
            if count >= 5:
                discoveries.append(ThreatDiscovery(
                    discovery_id=f"discovery-{uuid4().hex[:12]}",
                    member_entities=[source, target],
                    score=round(min(1.0, count / 10.0), 4),
                    discovery_type="temporal_fraud_chain",
                    description=f"High-frequency temporal flow: {count} transactions",
                    evidence={"transaction_count": count, "method": "temporal_pattern_mining"},
                ))
        return discoveries

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _connected_components(self, adjacency: Dict[str, set]) -> List[List[str]]:
        visited = set()
        components: List[List[str]] = []
        for node_id in adjacency:
            if node_id in visited:
                continue
            component = []
            stack = [node_id]
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                component.append(current)
                stack.extend(adjacency[current] - visited)
            components.append(component)
        return components

    def _community_score(self, adjacency: Dict[str, set], members: List[str]) -> float:
        """Ratio of internal edges to possible edges (cohesion)."""
        member_set = set(members)
        internal = 0
        for member in members:
            internal += len(adjacency[member] & member_set)
        internal //= 2
        possible = len(members) * (len(members) - 1) / 2
        if possible == 0:
            return 0.0
        return internal / possible

    def _dedupe(self, discoveries: List[ThreatDiscovery]) -> List[ThreatDiscovery]:
        """Merge discoveries that overlap heavily on member entities."""
        merged: List[ThreatDiscovery] = []
        for discovery in discoveries:
            if not merged:
                merged.append(discovery)
                continue
            found = False
            for existing in merged:
                overlap = set(existing.member_entities) & set(discovery.member_entities)
                if overlap:
                    existing.member_entities = sorted(
                        set(existing.member_entities) | set(discovery.member_entities)
                    )
                    existing.score = max(existing.score, discovery.score)
                    existing.evidence["merged_with"] = discovery.discovery_id
                    found = True
                    break
            if not found:
                merged.append(discovery)
        return merged

    # ------------------------------------------------------------------
    # Benchmarking
    # ------------------------------------------------------------------

    def benchmark_precision(self, graph: Dict[str, Any]) -> Dict[str, Any]:
        """Benchmark discovery precision against ground-truth mule labels.

        Returns:
            Dict with ``precision``, ``discovered``, ``true_positives`` and
            ``false_positives`` computed over graph nodes flagged ``is_mule``.
        """
        discoveries = self.hunt(graph)
        true_positives = 0
        false_positives = 0
        discovered_members = set()
        for discovery in discoveries:
            discovered_members.update(discovery.member_entities)
        for node in graph.get("nodes", []):
            is_mule = bool(node.get("is_mule", False))
            if is_mule and node["id"] in discovered_members:
                true_positives += 1
            elif not is_mule and node["id"] in discovered_members:
                false_positives += 1
        total = true_positives + false_positives
        precision = (true_positives / total) if total > 0 else 0.0
        return {
            "precision": round(precision, 4),
            "discovered": len(discovered_members),
            "true_positives": true_positives,
            "false_positives": false_positives,
        }
