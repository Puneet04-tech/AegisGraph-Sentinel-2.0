"""
Compliance Knowledge Graph for Regulatory Fabric.

Maintains relationships between regulations, controls, policies, and entities.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
import threading


@dataclass
class GraphNode:
    """Knowledge graph node."""
    node_id: str
    node_type: str  # regulation, control, policy, requirement
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Knowledge graph edge."""
    edge_id: str
    source_id: str
    target_id: str
    relationship: str  # maps_to, requires, implements, etc.
    weight: float = 1.0


class ComplianceKnowledgeGraph:
    """Knowledge graph for compliance relationships.
    
    Maintains a graph of relationships between regulations, controls,
    policies, and other compliance entities.
    """

    def __init__(self, store: Any):
        """Initialize the knowledge graph.
        
        Args:
            store: Compliance store instance
        """
        self.store = store
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._adjacency: Dict[str, List[str]] = {}  # node_id -> list of connected node_ids
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
        
        # Add regulation nodes
        for reg in self.store.regulations.values():
            node = GraphNode(
                node_id=f"reg_{reg.get('regulation_id')}",
                node_type="regulation",
                label=reg.get("name", ""),
                properties=reg,
            )
            self._add_node(node)
            stats["nodes_created"] += 1
            
            # Add requirement nodes
            for req in reg.get("requirements", []):
                req_node = GraphNode(
                    node_id=f"req_{req.get('id', '')}",
                    node_type="requirement",
                    label=req.get("name", ""),
                    properties=req,
                )
                self._add_node(req_node)
                stats["nodes_created"] += 1
                
                # Connect requirement to regulation
                self._add_edge(GraphEdge(
                    edge_id=f"edge_{req_node.node_id}_{node.node_id}",
                    source_id=node.node_id,
                    target_id=req_node.node_id,
                    relationship="contains",
                ))
                stats["edges_created"] += 1
        
        # Add control nodes
        for ctrl in self.store.controls.values():
            node = GraphNode(
                node_id=f"ctrl_{ctrl.get('control_id')}",
                node_type="control",
                label=ctrl.get("control_name", ""),
                properties=ctrl,
            )
            self._add_node(node)
            stats["nodes_created"] += 1
        
        # Add control mappings
        for mapping in self.store.control_mappings.values():
            reg_id = mapping.get("regulation_id", "")
            ctrl_id = mapping.get("control_id", "")
            req_id = mapping.get("requirement_id", "")
            
            reg_node_id = f"reg_{reg_id}"
            ctrl_node_id = f"ctrl_{ctrl_id}"
            req_node_id = f"req_{req_id}" if req_id else None
            
            # Connect control to regulation
            if reg_node_id in self._nodes and ctrl_node_id in self._nodes:
                self._add_edge(GraphEdge(
                    edge_id=f"edge_{ctrl_node_id}_{reg_node_id}",
                    source_id=ctrl_node_id,
                    target_id=reg_node_id,
                    relationship="maps_to",
                    weight=mapping.get("confidence", 1.0),
                ))
                stats["edges_created"] += 1
            
            # Connect control to requirement if specified
            if req_node_id and req_node_id in self._nodes and ctrl_node_id in self._nodes:
                self._add_edge(GraphEdge(
                    edge_id=f"edge_{ctrl_node_id}_{req_node_id}",
                    source_id=ctrl_node_id,
                    target_id=req_node_id,
                    relationship="implements",
                    weight=mapping.get("confidence", 1.0),
                ))
                stats["edges_created"] += 1
        
        # Add policy nodes
        for policy in self.store.policies.values():
            node = GraphNode(
                node_id=f"pol_{policy.get('policy_id')}",
                node_type="policy",
                label=policy.get("name", ""),
                properties=policy,
            )
            self._add_node(node)
            stats["nodes_created"] += 1
            
            # Connect policy to related controls
            for ctrl_id in policy.get("related_controls", []):
                ctrl_node_id = f"ctrl_{ctrl_id}"
                if ctrl_node_id in self._nodes:
                    self._add_edge(GraphEdge(
                        edge_id=f"edge_{node.node_id}_{ctrl_node_id}",
                        source_id=node.node_id,
                        target_id=ctrl_node_id,
                        relationship="governs",
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

    def find_connected_controls(self, regulation_id: str) -> List[str]:
        """Find all controls connected to a regulation.
        
        Args:
            regulation_id: Regulation ID
            
        Returns:
            List of control IDs
        """
        reg_node_id = f"reg_{regulation_id}"
        control_ids = []
        
        for edge in self._edges.values():
            if edge.target_id == reg_node_id and edge.relationship == "maps_to":
                ctrl_node_id = edge.source_id
                if ctrl_node_id.startswith("ctrl_"):
                    control_ids.append(ctrl_node_id[5:])  # Remove "ctrl_" prefix
        
        return control_ids

    def find_regulations_for_control(self, control_id: str) -> List[str]:
        """Find all regulations a control maps to.
        
        Args:
            control_id: Control ID
            
        Returns:
            List of regulation IDs
        """
        ctrl_node_id = f"ctrl_{control_id}"
        regulation_ids = []
        
        for edge in self._edges.values():
            if edge.source_id == ctrl_node_id and edge.relationship == "maps_to":
                reg_node_id = edge.target_id
                if reg_node_id.startswith("reg_"):
                    regulation_ids.append(reg_node_id[4:])  # Remove "reg_" prefix
        
        return regulation_ids

    def find_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """Find a path between two nodes.
        
        Args:
            source_id: Source node ID (without prefix)
            target_id: Target node ID (without prefix)
            
        Returns:
            Path as list of node IDs or None
        """
        source_node_id = self._resolve_node_id(source_id)
        target_node_id = self._resolve_node_id(target_id)
        
        if not source_node_id or not target_node_id:
            return None
        
        # BFS to find shortest path
        visited = {source_node_id}
        queue = [(source_node_id, [source_node_id])]
        
        while queue:
            current, path = queue.pop(0)
            
            if current == target_node_id:
                return path
            
            for neighbor in self._adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return None

    def _resolve_node_id(self, node_id: str) -> Optional[str]:
        """Resolve a partial node ID to full node ID."""
        # Try direct match
        if node_id in self._nodes:
            return node_id
        
        # Try with prefixes
        prefixes = ["reg_", "ctrl_", "req_", "pol_"]
        for prefix in prefixes:
            full_id = f"{prefix}{node_id}"
            if full_id in self._nodes:
                return full_id
        
        return None

    def get_impact_analysis(self, control_id: str) -> Dict[str, Any]:
        """Analyze the impact of a control.
        
        Args:
            control_id: Control ID
            
        Returns:
            Impact analysis
        """
        ctrl_node_id = f"ctrl_{control_id}"
        
        # Find all regulations this control maps to
        mapped_regs = self.find_regulations_for_control(control_id)
        
        # Find all requirements this control implements
        implemented_reqs = []
        for edge in self._edges.values():
            if edge.source_id == ctrl_node_id and edge.relationship == "implements":
                req_node_id = edge.target_id
                if req_node_id.startswith("req_"):
                    implemented_reqs.append(req_node_id[4:])
        
        # Find all policies this control supports
        governing_policies = []
        for edge in self._edges.values():
            if edge.target_id == ctrl_node_id and edge.relationship == "governs":
                pol_node_id = edge.source_id
                if pol_node_id.startswith("pol_"):
                    governing_policies.append(pol_node_id[4:])
        
        return {
            "control_id": control_id,
            "mapped_regulations": mapped_regs,
            "implemented_requirements": implemented_reqs,
            "governing_policies": governing_policies,
            "impact_score": len(mapped_regs) + len(implemented_reqs) * 0.5,
        }

    def get_coverage_analysis(self, regulation_id: str) -> Dict[str, Any]:
        """Analyze control coverage for a regulation.
        
        Args:
            regulation_id: Regulation ID
            
        Returns:
            Coverage analysis
        """
        reg_node_id = f"reg_{regulation_id}"
        
        # Get regulation node
        reg_node = self._nodes.get(reg_node_id)
        if not reg_node:
            return {"error": "Regulation not found"}
        
        # Get all requirement nodes
        requirements = []
        for edge in self._edges.values():
            if edge.target_id == reg_node_id and edge.relationship == "contains":
                req_node_id = edge.source_id
                req_node = self._nodes.get(req_node_id)
                if req_node:
                    requirements.append({
                        "id": req_node.node_id[4:],  # Remove "req_" prefix
                        "name": req_node.label,
                        "properties": req_node.properties,
                    })
        
        # Get all controls mapping to this regulation
        controls = self.find_connected_controls(regulation_id)
        
        # Analyze requirement coverage
        covered_reqs = set()
        for ctrl_id in controls:
            ctrl_node_id = f"ctrl_{ctrl_id}"
            for edge in self._edges.values():
                if edge.source_id == ctrl_node_id and edge.relationship == "implements":
                    req_node_id = edge.target_id
                    covered_reqs.add(req_node_id)
        
        coverage_details = []
        for req in requirements:
            req_node_id = f"req_{req['id']}"
            is_covered = req_node_id in covered_reqs
            
            # Find covering controls
            covering_ctrls = []
            for ctrl_id in controls:
                ctrl_node_id = f"ctrl_{ctrl_id}"
                for edge in self._edges.values():
                    if (edge.source_id == ctrl_node_id and 
                        edge.target_id == req_node_id and 
                        edge.relationship == "implements"):
                        covering_ctrls.append(ctrl_id)
            
            coverage_details.append({
                "requirement": req,
                "covered": is_covered,
                "covering_controls": covering_ctrls,
            })
        
        covered_count = sum(1 for c in coverage_details if c["covered"])
        
        return {
            "regulation_id": regulation_id,
            "regulation_name": reg_node.label,
            "total_requirements": len(requirements),
            "covered_requirements": covered_count,
            "coverage_percentage": (covered_count / len(requirements) * 100) if requirements else 0,
            "uncovered_requirements": [
                c["requirement"] for c in coverage_details if not c["covered"]
            ],
            "coverage_details": coverage_details,
        }

    def get_graph_stats(self) -> Dict[str, Any]:
        """Get knowledge graph statistics."""
        node_types = {}
        for node in self._nodes.values():
            node_types[node.node_type] = node_types.get(node.node_type, 0) + 1
        
        relationships = {}
        for edge in self._edges.values():
            relationships[edge.relationship] = relationships.get(edge.relationship, 0) + 1
        
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "nodes_by_type": node_types,
            "relationships": relationships,
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


def get_knowledge_graph() -> ComplianceKnowledgeGraph:
    """Get the global knowledge graph instance."""
    from .store import get_compliance_store
    store = get_compliance_store()
    return ComplianceKnowledgeGraph(store)