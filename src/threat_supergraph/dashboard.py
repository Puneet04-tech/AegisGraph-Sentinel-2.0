"""
Global Intelligence Dashboard
Executive dashboard for the threat supergraph.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import EntityType, RelationshipType
from .store import SupergraphStore, get_supergraph_store
from .supergraph_engine import ThreatSupergraphEngine, get_supergraph_engine


class GlobalIntelligenceDashboard:
    """Dashboard for global threat intelligence."""
    
    def __init__(
        self,
        store: Optional[SupergraphStore] = None,
        engine: Optional[ThreatSupergraphEngine] = None,
    ):
        self.store = store or get_supergraph_store()
        self.engine = engine or get_supergraph_engine()
    
    def generate_dashboard(
        self,
        time_range_days: int = 30,
    ) -> Dict[str, Any]:
        """Generate the global intelligence dashboard."""
        stats = self.store.get_graph_stats()
        
        top_entities = self._get_top_entities(limit=10)
        
        threat_actors = self._get_entities_by_type(EntityType.THREAT_ACTOR, limit=10)
        
        campaigns = self._get_entities_by_type(EntityType.CAMPAIGN, limit=10)
        
        high_risk_entities = self._get_high_risk_entities(limit=20)
        
        relationship_summary = self._get_relationship_summary()
        
        return {
            "dashboard_id": str(self.store.nodes),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range_days": time_range_days,
            "graph_stats": stats,
            "top_entities": top_entities,
            "threat_actors": threat_actors,
            "campaigns": campaigns,
            "high_risk_entities": high_risk_entities,
            "relationship_summary": relationship_summary,
        }
    
    def _get_top_entities(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top entities by threat score."""
        entities = list(self.store.nodes.values())
        entities.sort(key=lambda x: x.threat_score, reverse=True)
        
        return [
            {
                "node_id": e.node_id,
                "name": e.name,
                "entity_type": e.entity_type.value,
                "threat_score": e.threat_score,
                "risk_level": e.risk_level,
            }
            for e in entities[:limit]
        ]
    
    def _get_entities_by_type(
        self,
        entity_type: EntityType,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get entities by type."""
        entities = []
        
        for node in self.store.nodes.values():
            if node.entity_type == entity_type:
                entities.append({
                    "node_id": node.node_id,
                    "name": node.name,
                    "threat_score": node.threat_score,
                    "risk_level": node.risk_level,
                    "last_seen": node.last_seen.isoformat(),
                })
        
        entities.sort(key=lambda x: x["threat_score"], reverse=True)
        return entities[:limit]
    
    def _get_high_risk_entities(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get high risk entities."""
        high_risk = []
        
        for node in self.store.nodes.values():
            if node.risk_level in ["CRITICAL", "HIGH"]:
                high_risk.append({
                    "node_id": node.node_id,
                    "name": node.name,
                    "entity_type": node.entity_type.value,
                    "threat_score": node.threat_score,
                    "risk_level": node.risk_level,
                    "tags": node.tags,
                })
        
        return high_risk[:limit]
    
    def _get_relationship_summary(self) -> Dict[str, Any]:
        """Get relationship summary."""
        summary = {}
        
        for rel_type in RelationshipType:
            edge_ids = self.store.relationship_index.get(rel_type, set())
            summary[rel_type.value] = len(edge_ids)
        
        return {
            "total_relationships": len(self.store.edges),
            "by_type": summary,
        }
    
    def get_entity_insights(
        self,
        entity_id: str,
    ) -> Dict[str, Any]:
        """Get insights for a specific entity."""
        node = self.store.get_node(entity_id)
        if not node:
            return {"error": "Entity not found"}
        
        neighbors = self.store.get_neighbors(entity_id, max_hops=2)
        
        cluster = self.engine.get_entity_cluster(entity_id, depth=2)
        
        risk_score = self.engine.get_risk_score(entity_id)
        
        return {
            "entity": node.to_dict(),
            "neighbor_count": len(neighbors),
            "cluster_size": len(cluster),
            "risk_score": risk_score,
            "connections": [
                {
                    "node_id": n.node_id,
                    "name": n.name,
                    "entity_type": n.entity_type.value,
                }
                for n in cluster[:20]
            ],
        }


def get_dashboard() -> GlobalIntelligenceDashboard:
    """Get the global dashboard instance."""
    global _dashboard
    if _dashboard is None:
        _dashboard = GlobalIntelligenceDashboard()
    return _dashboard


_dashboard: Optional[GlobalIntelligenceDashboard] = None