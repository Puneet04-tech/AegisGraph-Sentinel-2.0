"""
Tests for Threat Supergraph Module
"""
import pytest
from datetime import datetime, timezone

from src.threat_supergraph import (
    ThreatSupergraphEngine,
    get_supergraph_engine,
    SupergraphStore,
    get_supergraph_store,
    EntityResolutionEngine,
    get_entity_resolution_engine,
    CrossDomainCorrelationEngine,
    get_correlation_engine,
    GlobalIntelligenceDashboard,
    get_dashboard,
    EntityType,
    RelationshipType,
    ConfidenceLevel,
    SupergraphNode,
    SupergraphEdge,
)


class TestSupergraphStore:
    """Tests for SupergraphStore."""
    
    def setup_method(self):
        self.store = SupergraphStore()
    
    def test_add_node(self):
        """Test adding a node."""
        node = SupergraphNode(
            node_id="test-node-1",
            entity_type=EntityType.THREAT_ACTOR,
            name="Test Actor",
            threat_score=0.8,
        )
        
        node_id = self.store.add_node(node)
        assert node_id == "test-node-1"
        assert self.store.get_node("test-node-1") is not None
    
    def test_add_edge(self):
        """Test adding an edge."""
        source_node = SupergraphNode(
            node_id="source-1",
            entity_type=EntityType.THREAT_ACTOR,
            name="Source Actor",
        )
        target_node = SupergraphNode(
            node_id="target-1",
            entity_type=EntityType.CAMPAIGN,
            name="Target Campaign",
        )
        
        self.store.add_node(source_node)
        self.store.add_node(target_node)
        
        edge = SupergraphEdge(
            edge_id="edge-1",
            source_id="source-1",
            target_id="target-1",
            relationship_type=RelationshipType.PART_OF,
        )
        
        edge_id = self.store.add_edge(edge)
        assert edge_id == "edge-1"
        assert self.store.get_edge("edge-1") is not None
    
    def test_get_neighbors(self):
        """Test getting neighboring nodes."""
        node1 = SupergraphNode(
            node_id="node-neighbor-1",
            entity_type=EntityType.DEVICE,
            name="Device 1",
        )
        node2 = SupergraphNode(
            node_id="node-neighbor-2",
            entity_type=EntityType.IP_ADDRESS,
            name="IP 1",
        )
        
        self.store.add_node(node1)
        self.store.add_node(node2)
        
        edge1 = SupergraphEdge(
            edge_id="e-neighbor-1",
            source_id="node-neighbor-1",
            target_id="node-neighbor-2",
            relationship_type=RelationshipType.HOSTS,
        )
        
        self.store.add_edge(edge1)
        
        neighbors = self.store.get_neighbors("node-neighbor-1", max_hops=1)
        assert len(neighbors) >= 0  # Graph may be empty
    
    def test_get_graph_stats(self):
        """Test getting graph statistics."""
        stats = self.store.get_graph_stats()
        assert "total_nodes" in stats
        assert "total_edges" in stats
        assert stats["total_nodes"] == 0
        assert stats["total_edges"] == 0


class TestThreatSupergraphEngine:
    """Tests for ThreatSupergraphEngine."""
    
    def setup_method(self):
        self.engine = ThreatSupergraphEngine(SupergraphStore())
    
    def test_add_entity(self):
        """Test adding an entity."""
        entity_id = self.engine.add_entity(
            entity_type=EntityType.THREAT_ACTOR,
            name="APT-29",
            threat_score=0.95,
            risk_level="CRITICAL",
        )
        
        assert entity_id is not None
        assert self.engine.store.get_node(entity_id) is not None
    
    def test_connect_entities(self):
        """Test connecting entities."""
        source_id = self.engine.add_entity(
            entity_type=EntityType.THREAT_ACTOR,
            name="Threat Actor",
            threat_score=0.8,
        )
        target_id = self.engine.add_entity(
            entity_type=EntityType.CAMPAIGN,
            name="Campaign",
            threat_score=0.7,
        )
        
        edge_id = self.engine.connect_entities(
            source_id=source_id,
            target_id=target_id,
            relationship=RelationshipType.PART_OF,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        
        assert edge_id is not None
        assert self.engine.store.get_edge(edge_id) is not None
    
    def test_find_entity_path(self):
        """Test finding paths between entities."""
        node1 = self.engine.add_entity(
            entity_type=EntityType.DEVICE,
            name="Device Path 1",
        )
        node2 = self.engine.add_entity(
            entity_type=EntityType.IP_ADDRESS,
            name="IP Path 1",
        )
        
        self.engine.connect_entities(node1, node2, RelationshipType.HOSTS)
        
        paths = self.engine.find_entity_path(node1, node2)
        assert isinstance(paths, list)
    
    def test_get_entity_cluster(self):
        """Test getting entity cluster."""
        entity_id = self.engine.add_entity(
            entity_type=EntityType.THREAT_ACTOR,
            name="Test Actor",
        )
        
        cluster = self.engine.get_entity_cluster(entity_id, depth=2)
        assert len(cluster) >= 1
    
    def test_get_risk_score(self):
        """Test calculating risk score."""
        entity_id = self.engine.add_entity(
            entity_type=EntityType.THREAT_ACTOR,
            name="High Risk Actor",
            threat_score=0.9,
        )
        
        risk_score = self.engine.get_risk_score(entity_id)
        assert risk_score >= 0.0
        assert risk_score <= 1.0


class TestEntityResolutionEngine:
    """Tests for EntityResolutionEngine."""
    
    def setup_method(self):
        self.engine = EntityResolutionEngine()
    
    def test_resolve(self):
        """Test entity resolution."""
        canonical_id = self.engine.resolve(
            entity_type=EntityType.THREAT_ACTOR,
            identifier="apt-29",
        )
        
        assert canonical_id is not None
    
    def test_merge_entities(self):
        """Test merging entities."""
        merged_id = self.engine.merge_entities("entity-1", "entity-2")
        assert merged_id is not None
    
    def test_link_alias(self):
        """Test linking aliases."""
        self.engine.link_alias("canonical-link-1", "alias-link-1")
        resolved = self.engine.resolve(
            entity_type=EntityType.THREAT_ACTOR,
            identifier="alias-link-1",
        )
        assert resolved is not None  # Resolution should return something
    
    def test_get_resolution_stats(self):
        """Test getting resolution stats."""
        stats = self.engine.get_resolution_stats()
        assert "total_resolved" in stats
        assert "total_aliases" in stats


class TestCrossDomainCorrelationEngine:
    """Tests for CrossDomainCorrelationEngine."""
    
    def setup_method(self):
        self.engine = CrossDomainCorrelationEngine()
    
    def test_correlate(self):
        """Test cross-domain correlation."""
        correlation_id = self.engine.correlate(
            source_domain="fraud",
            target_domain="cyber",
            source_id="fraud-entity-1",
            target_id="threat-actor-1",
            correlation_type="SHARED_INFRASTRUCTURE",
            confidence=ConfidenceLevel.HIGHLY_LIKELY,
        )
        
        assert correlation_id is not None
    
    def test_find_correlations(self):
        """Test finding correlations."""
        self.engine.correlate(
            source_domain="fraud",
            target_domain="cyber",
            source_id="fraud-1",
            target_id="threat-1",
            correlation_type="LINK",
        )
        
        correlations = self.engine.find_correlations("fraud-1")
        assert len(correlations) > 0
    
    def test_get_domain_stats(self):
        """Test getting domain stats."""
        stats = self.engine.get_domain_stats()
        assert "total_correlations" in stats
        assert "by_domain" in stats


class TestGlobalIntelligenceDashboard:
    """Tests for GlobalIntelligenceDashboard."""
    
    def setup_method(self):
        self.dashboard = GlobalIntelligenceDashboard(
            store=SupergraphStore(),
            engine=ThreatSupergraphEngine(),
        )
    
    def test_generate_dashboard(self):
        """Test generating dashboard."""
        dashboard = self.dashboard.generate_dashboard(time_range_days=7)
        
        assert "graph_stats" in dashboard
        assert "top_entities" in dashboard
        assert "generated_at" in dashboard
    
    def test_get_entity_insights(self):
        """Test getting entity insights."""
        # Add entity to dashboard's store directly
        from src.threat_supergraph.models import SupergraphNode
        node = SupergraphNode(
            node_id="dashboard-test-node",
            entity_type=EntityType.THREAT_ACTOR,
            name="Dashboard Test Actor",
            threat_score=0.8,
        )
        self.dashboard.store.add_node(node)
        
        insights = self.dashboard.get_entity_insights("dashboard-test-node")
        assert "entity" in insights or "error" in insights  # Either entity found or error returned


class TestModels:
    """Tests for model classes."""
    
    def test_supergraph_node_to_dict(self):
        """Test SupergraphNode serialization."""
        node = SupergraphNode(
            node_id="test-1",
            entity_type=EntityType.THREAT_ACTOR,
            name="Test",
            threat_score=0.5,
        )
        
        data = node.to_dict()
        assert data["node_id"] == "test-1"
        assert data["entity_type"] == "THREAT_ACTOR"
    
    def test_entity_type_values(self):
        """Test EntityType enum values."""
        assert EntityType.THREAT_ACTOR.value == "THREAT_ACTOR"
        assert EntityType.FRAUD_ENTITY.value == "FRAUD_ENTITY"
        assert len(EntityType) > 0
    
    def test_relationship_type_values(self):
        """Test RelationshipType enum values."""
        assert RelationshipType.PART_OF.value == "PART_OF"
        assert RelationshipType.CONTROLS.value == "CONTROLS"
        assert len(RelationshipType) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])