"""
Knowledge Engine
Core knowledge management and retrieval.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4
import re

from .models import (
    KnowledgeEntry,
    KnowledgeType,
    KnowledgeStatus,
    AccessLevel,
    KnowledgeGraph,
    KnowledgeRecommendation,
)


class KnowledgeEngine:
    """Main knowledge engine."""
    
    def __init__(self):
        self.entries: Dict[str, KnowledgeEntry] = {}
        self.graphs: Dict[str, KnowledgeGraph] = {}
        self._initialize_default_knowledge()
    
    def _initialize_default_knowledge(self):
        """Initialize with default knowledge entries."""
        entries = [
            KnowledgeEntry(
                entry_id="kb-001",
                title="Mule Account Detection Patterns",
                content="Patterns for detecting mule accounts in financial transactions",
                knowledge_type=KnowledgeType.FRAUD_PATTERN,
                status=KnowledgeStatus.APPROVED,
                tags=["mule", "detection", "fraud"],
            ),
            KnowledgeEntry(
                entry_id="kb-002",
                title="Phishing Attack Indicators",
                content="Common indicators of phishing attacks",
                knowledge_type=KnowledgeType.THREAT_INTEL,
                status=KnowledgeStatus.APPROVED,
                tags=["phishing", "indicators", "detection"],
            ),
            KnowledgeEntry(
                entry_id="kb-003",
                title="AML High-Risk Countries",
                content="List of high-risk countries for AML monitoring",
                knowledge_type=KnowledgeType.AML_INDICATOR,
                status=KnowledgeStatus.APPROVED,
                access_level=AccessLevel.RESTRICTED,
                tags=["AML", "high-risk", "countries"],
            ),
        ]
        
        for entry in entries:
            self.entries[entry.entry_id] = entry
    
    def store_entry(
        self,
        title: str,
        content: str,
        knowledge_type: KnowledgeType,
        created_by: str = "",
        tags: Optional[List[str]] = None,
        access_level: AccessLevel = AccessLevel.PUBLIC,
    ) -> str:
        """Store a new knowledge entry."""
        entry_id = str(uuid4())
        
        entry = KnowledgeEntry(
            entry_id=entry_id,
            title=title,
            content=content,
            knowledge_type=knowledge_type,
            tags=tags or [],
            access_level=access_level,
            created_by=created_by,
        )
        
        self.entries[entry_id] = entry
        return entry_id
    
    def get_entry(self, entry_id: str) -> Optional[KnowledgeEntry]:
        """Get a knowledge entry by ID."""
        return self.entries.get(entry_id)
    
    def update_entry(
        self,
        entry_id: str,
        status: Optional[KnowledgeStatus] = None,
        content: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> bool:
        """Update a knowledge entry."""
        entry = self.entries.get(entry_id)
        if not entry:
            return False
        
        if status:
            entry.status = status
        if content:
            entry.content = content
        if tags:
            entry.tags = tags
        
        entry.updated_at = datetime.now(timezone.utc)
        return True
    
    def search(
        self,
        query: str,
        knowledge_type: Optional[KnowledgeType] = None,
        tags: Optional[List[str]] = None,
        access_level: Optional[AccessLevel] = None,
        limit: int = 10,
    ) -> List[KnowledgeEntry]:
        """Search knowledge entries."""
        results = []
        
        for entry in self.entries.values():
            if access_level and entry.access_level != access_level:
                continue
            
            if knowledge_type and entry.knowledge_type != knowledge_type:
                continue
            
            if tags and not any(tag in entry.tags for tag in tags):
                continue
            
            query_lower = query.lower()
            if (query_lower in entry.title.lower() or 
                query_lower in entry.content.lower() or
                any(query_lower in tag.lower() for tag in entry.tags)):
                results.append(entry)
        
        return results[:limit]
    
    def add_relationship(
        self,
        entry_id: str,
        related_entry_id: str,
        relationship_type: str = "RELATED",
    ) -> bool:
        """Add relationship between entries."""
        entry = self.entries.get(entry_id)
        related = self.entries.get(related_entry_id)
        
        if not entry or not related:
            return False
        
        if related_entry_id not in entry.related_entries:
            entry.related_entries.append(related_entry_id)
        
        if entry_id not in related.related_entries:
            related.related_entries.append(entry_id)
        
        return True
    
    def get_related(self, entry_id: str) -> List[KnowledgeEntry]:
        """Get related knowledge entries."""
        entry = self.entries.get(entry_id)
        if not entry:
            return []
        
        return [
            self.entries[eid]
            for eid in entry.related_entries
            if eid in self.entries
        ]


class KnowledgeGraphManager:
    """Manage knowledge graphs."""
    
    def __init__(self, engine: Optional[KnowledgeEngine] = None):
        self.engine = engine or get_knowledge_engine()
        self.graphs: Dict[str, KnowledgeGraph] = {}
    
    def create_graph(
        self,
        name: str,
        entry_ids: Optional[List[str]] = None,
    ) -> str:
        """Create a knowledge graph."""
        graph_id = str(uuid4())
        
        nodes = []
        edges = []
        
        if entry_ids:
            for entry_id in entry_ids:
                entry = self.engine.get_entry(entry_id)
                if entry:
                    nodes.append({
                        "id": entry.entry_id,
                        "label": entry.title,
                        "type": entry.knowledge_type.value,
                    })
        
        for i, node1 in enumerate(nodes):
            for node2 in nodes[i+1:]:
                edges.append({
                    "source": node1["id"],
                    "target": node2["id"],
                    "type": "KNOWS",
                })
        
        graph = KnowledgeGraph(
            graph_id=graph_id,
            name=name,
            nodes=nodes,
            edges=edges,
        )
        
        self.graphs[graph_id] = graph
        return graph_id
    
    def get_graph(self, graph_id: str) -> Optional[KnowledgeGraph]:
        """Get a graph by ID."""
        return self.graphs.get(graph_id)
    
    def add_node(
        self,
        graph_id: str,
        node_id: str,
        label: str,
        node_type: str,
    ) -> bool:
        """Add a node to a graph."""
        graph = self.graphs.get(graph_id)
        if not graph:
            return False
        
        graph.nodes.append({
            "id": node_id,
            "label": label,
            "type": node_type,
        })
        return True
    
    def add_edge(
        self,
        graph_id: str,
        source_id: str,
        target_id: str,
        edge_type: str = "RELATED",
    ) -> bool:
        """Add an edge to a graph."""
        graph = self.graphs.get(graph_id)
        if not graph:
            return False
        
        graph.edges.append({
            "source": source_id,
            "target": target_id,
            "type": edge_type,
        })
        return True
    
    def correlate_entries(
        self,
        entry_ids: List[str],
    ) -> List[Dict[str, Any]]:
        """Correlate entries to find relationships."""
        correlations = []
        
        for i, entry1_id in enumerate(entry_ids):
            entry1 = self.engine.get_entry(entry1_id)
            if not entry1:
                continue
            
            for entry2_id in entry_ids[i+1:]:
                entry2 = self.engine.get_entry(entry2_id)
                if not entry2:
                    continue
                
                correlation_score = self._calculate_correlation(entry1, entry2)
                
                if correlation_score > 0.3:
                    correlations.append({
                        "entry1": entry1_id,
                        "entry2": entry2_id,
                        "score": correlation_score,
                        "shared_tags": list(set(entry1.tags) & set(entry2.tags)),
                    })
        
        return correlations
    
    def _calculate_correlation(
        self,
        entry1: KnowledgeEntry,
        entry2: KnowledgeEntry,
    ) -> float:
        """Calculate correlation between two entries."""
        score = 0.0
        
        if entry1.knowledge_type == entry2.knowledge_type:
            score += 0.3
        
        shared_tags = set(entry1.tags) & set(entry2.tags)
        score += len(shared_tags) * 0.1
        
        if entry1.access_level == entry2.access_level:
            score += 0.1
        
        return min(1.0, score)


class KnowledgeRetrievalEngine:
    """Engine for knowledge retrieval and recommendations."""
    
    def __init__(self, engine: Optional[KnowledgeEngine] = None):
        self.engine = engine or get_knowledge_engine()
        self.audit_log: List[Dict[str, Any]] = []
    
    def retrieve(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
        max_results: int = 5,
    ) -> List[KnowledgeEntry]:
        """Retrieve knowledge based on query and context."""
        results = self.engine.search(query, limit=max_results * 2)
        
        if context:
            domain = context.get("domain")
            if domain:
                filtered = [r for r in results if domain.lower() in r.title.lower() or domain.lower() in r.content.lower()]
                if filtered:
                    results = filtered[:max_results]
        
        self._log_retrieval(query, len(results))
        return results[:max_results]
    
    def get_recommendations(
        self,
        user_id: str,
        context: Optional[Dict[str, Any]] = None,
        limit: int = 5,
    ) -> List[KnowledgeRecommendation]:
        """Get knowledge recommendations for a user."""
        recommendations = []
        
        if context:
            domain = context.get("domain", "")
            query = context.get("query", "")
            
            entries = self.engine.search(query or domain, limit=limit * 2)
            
            for entry in entries[:limit]:
                rec = KnowledgeRecommendation(
                    recommendation_id=str(uuid4()),
                    entry_id=entry.entry_id,
                    reason=f"Based on {domain} context",
                    confidence=0.8,
                )
                recommendations.append(rec)
        
        return recommendations
    
    def _log_retrieval(self, query: str, result_count: int):
        """Log a retrieval action."""
        self.audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "query": query,
            "results": result_count,
        })


def get_knowledge_engine() -> KnowledgeEngine:
    """Get the global knowledge engine instance."""
    global _knowledge_engine
    if _knowledge_engine is None:
        _knowledge_engine = KnowledgeEngine()
    return _knowledge_engine


_knowledge_engine: Optional[KnowledgeEngine] = None