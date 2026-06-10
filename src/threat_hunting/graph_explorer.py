"""
Graph Intelligence Explorer Engine for AI Threat Hunting
"""

from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timezone

from .models import AttackPath
from .store import ThreatHuntingStore, get_store


class GraphIntelligenceExplorer:
    """Engine to analyze entity relationship graphs and reconstruct attack paths."""

    def __init__(self, store: Optional[ThreatHuntingStore] = None):
        self.store = store or get_store()

    def discover_attack_paths(
        self,
        start_entity: str,
        relationships: List[Dict[str, Any]],
        max_depth: int = 3,
    ) -> List[AttackPath]:
        """Traverse relationships to discover multi-hop paths to known threat targets."""
        adj = {}
        for rel in relationships:
            u = rel.get("from_id")
            v = rel.get("to_id")
            rel_type = rel.get("type", "link")
            if u and v:
                if u not in adj:
                    adj[u] = []
                adj[u].append((v, rel_type))

        paths: List[AttackPath] = []
        visited = set()

        def dfs(node, current_path_nodes, current_path_edges, depth):
            if depth > max_depth:
                return

            # If we reached a node that is flagged with high risk, record it
            is_threat = False
            score = self.store.get_threat_score(node)
            if score and score.score > 0.6:
                is_threat = True

            if is_threat and len(current_path_nodes) > 1:
                risk_score = score.score if score else 0.5
                paths.append(
                    AttackPath(
                        nodes=list(current_path_nodes),
                        edges=list(current_path_edges),
                        risk_score=risk_score,
                        description=f"Path from {start_entity} to threat entity {node} via {len(current_path_edges)} hops",
                    )
                )

            visited.add(node)
            for neighbor, rel_type in adj.get(node, []):
                if neighbor not in visited:
                    next_nodes = current_path_nodes + [{"id": neighbor, "type": "entity"}]
                    next_edges_list = current_path_edges + [{"from": node, "to": neighbor, "type": rel_type}]
                    dfs(neighbor, next_nodes, next_edges_list, depth + 1)
            visited.remove(node)

        start_node_data = {"id": start_entity, "type": "entity"}
        dfs(start_entity, [start_node_data], [], 1)

        return paths
