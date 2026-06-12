"""
Threat Actor Knowledge Graph for Cyber-Fraud Warfare.

Maintains relationships between threat actors, campaigns, and entities.
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
import threading


@dataclass
class GraphNode:
    """Knowledge graph node."""
    node_id: str
    node_type: str  # actor, campaign, pattern, entity
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Knowledge graph edge."""
    edge_id: str
    source_id: str
    target_id: str
    relationship: str
    weight: float = 1.0


class ThreatKnowledgeGraph:
    """Knowledge graph for threat actor relationships.
    
    Maintains a graph of relationships between threat actors,
    campaigns, attack patterns, and target entities.
    """

    def __init__(self, store: Any):
        """Initialize the threat knowledge graph.
        
        Args:
            store: Warfare store instance
        """
        self.store = store
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._adjacency: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    def build_graph(self) -> Dict[str, Any]:
        """Build the knowledge graph from store data.
        
        Returns:
            Build statistics
        """
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._adjacency.clear()
        
        stats = {
            "nodes_created": 0,
            "edges_created": 0,
        }
        
        # Add threat actor nodes
        for actor in self.store.threat_actors.values():
            node = GraphNode(
                node_id=f"actor_{actor.get('actor_id')}",
                node_type="actor",
                label=actor.get("name", ""),
                properties=actor,
            )
            self._add_node(node)
            stats["nodes_created"] += 1
        
        # Add campaign nodes
        for campaign in self.store.campaigns.values():
            node = GraphNode(
                node_id=f"campaign_{campaign.get('campaign_id')}",
                node_type="campaign",
                label=campaign.get("name", ""),
                properties=campaign,
            )
            self._add_node(node)
            stats["nodes_created"] += 1
            
            # Connect campaigns to actors
            for actor_id in campaign.get("threat_actor_ids", []):
                self._add_edge(GraphEdge(
                    edge_id=f"edge_campaign_{campaign.get('campaign_id')}_actor_{actor_id}",
                    source_id=f"campaign_{campaign.get('campaign_id')}",
                    target_id=f"actor_{actor_id}",
                    relationship="attributed_to",
                    weight=0.8,
                ))
                stats["edges_created"] += 1
        
        # Add attack pattern nodes
        for pattern in self.store.attack_patterns.values():
            node = GraphNode(
                node_id=f"pattern_{pattern.get('pattern_id')}",
                node_type="pattern",
                label=pattern.get("name", ""),
                properties=pattern,
            )
            self._add_node(node)
            stats["nodes_created"] += 1
        
        # Add relationships
        for rel in self.store.threat_relationships.values():
            source_type = rel.get("source_type", "")
            target_type = rel.get("target_type", "")
            
            source_node_id = f"{source_type}_{rel.get('source_id')}"
            target_node_id = f"{target_type}_{rel.get('target_id')}"
            
            if source_node_id in self._nodes and target_node_id in self._nodes:
                self._add_edge(GraphEdge(
                    edge_id=rel.get("relationship_id"),
                    source_id=source_node_id,
                    target_id=target_node_id,
                    relationship=rel.get("relationship_type", ""),
                    weight=rel.get("strength", 1.0),
                ))
                stats["edges_created"] += 1
        
        return stats

    def _add_node(self, node: GraphNode) -> None:
        """Add a node to the graph."""
        with self._lock:
            self._nodes[node.node_id] = node
            if node.node_id not in self._adjacency:
                self._adjacency[node.node_id] = []

    def _add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph."""
        with self._lock:
            self._edges[edge.edge_id] = edge
            if edge.source_id not in self._adjacency:
                self._adjacency[edge.source_id] = []
            if edge.target_id not in self._adjacency:
                self._adjacency[edge.target_id] = []
            self._adjacency[edge.source_id].append(edge.target_id)

    def find_connected_entities(
        self,
        node_id: str,
        max_depth: int = 2,
    ) -> List[Dict[str, Any]]:
        """Find entities connected to a node.
        
        Args:
            node_id: Starting node ID (without prefix)
            max_depth: Maximum traversal depth
            
        Returns:
            List of connected entities with paths
        """
        # Resolve node ID
        if not node_id.startswith(("actor_", "campaign_", "pattern_")):
            node_id = f"actor_{node_id}"
        
        if node_id not in self._nodes:
            return []
        
        visited = {node_id}
        queue = [(node_id, 0, [])]
        results = []
        
        while queue:
            current, depth, path = queue.pop(0)
            
            if depth > 0:
                results.append({
                    "node_id": current,
                    "node": self._nodes.get(current),
                    "depth": depth,
                    "path": path,
                })
            
            if depth < max_depth:
                for neighbor in self._adjacency.get(current, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, depth + 1, path + [current]))
        
        return results

    def find_common_connections(
        self,
        node_id_1: str,
        node_id_2: str,
    ) -> List[Dict[str, Any]]:
        """Find common connections between two nodes.
        
        Args:
            node_id_1: First node ID
            node_id_2: Second node ID
            
        Returns:
            List of common connections
        """
        # Resolve node IDs
        if not node_id_1.startswith(("actor_", "campaign_", "pattern_")):
            node_id_1 = f"actor_{node_id_1}"
        if not node_id_2.startswith(("actor_", "campaign_", "pattern_")):
            node_id_2 = f"actor_{node_id_2}"
        
        connected_1 = set(
            r["node_id"] for r in self.find_connected_entities(node_id_1, max_depth=1)
        )
        connected_2 = set(
            r["node_id"] for r in self.find_connected_entities(node_id_2, max_depth=1)
        )
        
        common = connected_1 & connected_2
        
        return [
            {
                "node_id": node_id,
                "node": self._nodes.get(node_id),
            }
            for node_id in common
            if node_id in self._nodes
        ]

    def find_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """Find shortest path between two nodes.
        
        Args:
            source_id: Source node ID
            target_id: Target node ID
            
        Returns:
            Path as list of node IDs or None
        """
        # Resolve node IDs
        if not source_id.startswith(("actor_", "campaign_", "pattern_")):
            source_id = f"actor_{source_id}"
        if not target_id.startswith(("actor_", "campaign_", "pattern_")):
            target_id = f"campaign_{target_id}"
        
        if source_id not in self._nodes or target_id not in self._nodes:
            return None
        
        # BFS to find shortest path
        visited = {source_id}
        queue = [(source_id, [source_id])]
        
        while queue:
            current, path = queue.pop(0)
            
            if current == target_id:
                return path
            
            for neighbor in self._adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return None

    def get_actor_network(self, actor_id: str) -> Dict[str, Any]:
        """Get the actor's threat network.
        
        Args:
            actor_id: Actor ID
            
        Returns:
            Network data
        """
        actor_node_id = f"actor_{actor_id}"
        
        # Find directly connected actors
        direct_connections = self.find_connected_entities(actor_node_id, max_depth=1)
        actor_connections = [
            c for c in direct_connections
            if c["node_id"].startswith("actor_")
        ]
        
        # Find associated campaigns
        campaign_connections = [
            c for c in direct_connections
            if c["node_id"].startswith("campaign_")
        ]
        
        # Find shared patterns
        all_ttps: Dict[str, List[str]] = {}
        for conn in actor_connections:
            node = conn.get("node", {})
            if node:
                for ttp in node.properties.get("ttps", []):
                    if isinstance(ttp, dict):
                        ttp_id = ttp.get("id", "")
                    else:
                        ttp_id = str(ttp)
                    if ttp_id not in all_ttps:
                        all_ttps[ttp_id] = []
                    all_ttps[ttp_id].append(conn["node_id"])
        
        # Actors sharing TTPs
        shared_ttp_actors = {
            ttp_id: actors
            for ttp_id, actors in all_ttps.items()
            if len(actors) > 1
        }
        
        return {
            "actor_id": actor_id,
            "direct_connections": len(actor_connections),
            "associated_campaigns": len(campaign_connections),
            "shared_ttp_actors": shared_ttp_actors,
            "network_score": len(actor_connections) + len(campaign_connections),
        }

    def get_graph_stats(self) -> Dict[str, Any]:
        """Get knowledge graph statistics."""
        node_types = {}
        for node in self._nodes.values():
            node_types[node.node_type] = node_types.get(node.node_type, 0) + 1
        
        relationships = {}
        for edge in self._edges.values():
            relationships[edge.relationship] = relationships.get(edge.relationship, 0) + 1
        
        # Find most connected nodes
        connectivity = [
            {"node_id": node_id, "connections": len(neighbors)}
            for node_id, neighbors in self._adjacency.items()
        ]
        most_connected = sorted(connectivity, key=lambda x: x["connections"], reverse=True)[:10]
        
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "nodes_by_type": node_types,
            "relationships": relationships,
            "most_connected_nodes": most_connected,
        }

    def export_graph(self) -> Dict[str, Any]:
        """Export the knowledge graph as data."""
        nodes = [
            {
                "id": node.node_id,
                "type": node.node_type,
                "label": node.label,
                "properties": node.properties,
            }
            for node in self._nodes.values()
        ]
        
        edges = [
            {
                "id": edge.edge_id,
                "source": edge.source_id,
                "target": edge.target_id,
                "relationship": edge.relationship,
                "weight": edge.weight,
            }
            for edge in self._edges.values()
        ]
        
        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "node_count": len(nodes),
                "edge_count": len(edges),
            },
        }


def get_threat_knowledge_graph() -> ThreatKnowledgeGraph:
    """Get the global threat knowledge graph instance."""
    from .store import get_warfare_store
    store = get_warfare_store()
    return ThreatKnowledgeGraph(store)