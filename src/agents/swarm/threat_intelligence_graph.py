"""
Threat Intelligence Graph
AegisGraph Sentinel - Attack pattern and TTP knowledge graph.

A lightweight knowledge graph that maps discovered attack patterns, TTPs
(tactics, techniques and procedures) and fraud signatures so simulation
findings accumulate into a reusable intelligence base for continuous model
improvement.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from .models import AttackPattern

NODE_PATTERN = "attack_pattern"
NODE_TECHNIQUE = "technique"
NODE_TACTIC = "tactic"
NODE_ENTITY_TYPE = "entity_type"
NODE_INDICATOR = "indicator"
NODE_TTP = "ttp"


class ThreatIntelligenceGraph:
    """Knowledge graph of attack patterns and TTPs.

    Nodes represent patterns, techniques, tactics, entity types, indicators
    and TTP references. Edges connect a pattern to each of its dimensions.
    All operations are thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: List[Dict[str, str]] = []
        self._patterns: Dict[str, AttackPattern] = {}

    def add_patterns(self, patterns: List[AttackPattern]) -> int:
        """Insert patterns into the knowledge graph.

        Returns:
            Number of patterns successfully inserted.
        """
        added = 0
        with self._lock:
            for pattern in patterns:
                if pattern.pattern_id in self._patterns:
                    continue
                self._patterns[pattern.pattern_id] = pattern
                self._insert_pattern(pattern)
                added += 1
        return added

    def _insert_pattern(self, pattern: AttackPattern) -> None:
        pattern_node = self._upsert_node(pattern.pattern_id, NODE_PATTERN, {"name": pattern.name})
        technique_id = f"{NODE_TECHNIQUE}:{pattern.technique}"
        self._upsert_node(technique_id, NODE_TECHNIQUE, {"name": pattern.technique})
        self._add_edge(pattern_node, technique_id, "uses_technique")

        for tactic in pattern.tactics:
            tactic_id = f"{NODE_TACTIC}:{tactic}"
            self._upsert_node(tactic_id, NODE_TACTIC, {"name": tactic})
            self._add_edge(pattern_node, tactic_id, "maps_to_tactic")

        entity_id = f"{NODE_ENTITY_TYPE}:{pattern.entity_type}"
        self._upsert_node(entity_id, NODE_ENTITY_TYPE, {"name": pattern.entity_type})
        self._add_edge(pattern_node, entity_id, "targets_entity_type")

        for indicator in pattern.indicators:
            indicator_id = f"{NODE_INDICATOR}:{indicator}"
            self._upsert_node(indicator_id, NODE_INDICATOR, {"name": indicator})
            self._add_edge(pattern_node, indicator_id, "has_indicator")

        ttp_id = f"{NODE_TTP}:{pattern.ttp_reference}"
        self._upsert_node(ttp_id, NODE_TTP, {"name": pattern.ttp_reference})
        self._add_edge(pattern_node, ttp_id, "references_ttp")

    def _upsert_node(self, node_id: str, node_type: str, attrs: Dict[str, Any]) -> str:
        if node_id not in self._nodes:
            self._nodes[node_id] = {"id": node_id, "type": node_type, "attributes": attrs}
        else:
            self._nodes[node_id]["attributes"].update(attrs)
        return node_id

    def _add_edge(self, source: str, target: str, relation: str) -> None:
        edge = {"source": source, "target": target, "relation": relation}
        if edge not in self._edges:
            self._edges.append(edge)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_nodes(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._nodes.values())

    def get_edges(self) -> List[Dict[str, str]]:
        with self._lock:
            return list(self._edges)

    def get_patterns(self) -> List[AttackPattern]:
        with self._lock:
            return list(self._patterns.values())

    def get_pattern(self, pattern_id: str) -> Optional[AttackPattern]:
        with self._lock:
            return self._patterns.get(pattern_id)

    def node_count(self) -> int:
        with self._lock:
            return len(self._nodes)

    def edge_count(self) -> int:
        with self._lock:
            return len(self._edges)

    def pattern_count(self) -> int:
        with self._lock:
            return len(self._patterns)

    def techniques(self) -> List[str]:
        with self._lock:
            return [
                node["attributes"]["name"]
                for node in self._nodes.values()
                if node["type"] == NODE_TECHNIQUE
            ]

    def temporal_contexts(self) -> List[str]:
        with self._lock:
            return sorted({p.temporal_context for p in self._patterns.values()})

    def entity_types(self) -> List[str]:
        with self._lock:
            return sorted({p.entity_type for p in self._patterns.values()})

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "patterns": len(self._patterns),
                "nodes": len(self._nodes),
                "edges": len(self._edges),
                "techniques": len(self.techniques()),
            }
