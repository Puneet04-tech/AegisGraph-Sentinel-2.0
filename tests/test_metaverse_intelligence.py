"""
Tests for Metaverse Intelligence Module
"""
import pytest
from datetime import datetime, timezone

from src.metaverse_intelligence import (
    VisualizationEngine,
    get_visualization_engine,
    FraudRingDiscovery,
    InvestigationManager,
    get_fraud_ring_discovery,
    get_investigation_manager,
    VisualizationType,
    InvestigationStatus,
    VisualizationNode,
    VisualizationEdge,
    FraudRing,
    InvestigationCase,
)


class TestVisualizationEngine:
    """Tests for VisualizationEngine."""
    
    def setup_method(self):
        self.engine = VisualizationEngine()
    
    def test_create_network_graph(self):
        """Test network graph creation."""
        entities = [
            {"id": "e1", "name": "Entity 1", "type": "FRAUD"},
            {"id": "e2", "name": "Entity 2", "type": "FRAUD"},
        ]
        relationships = [
            {"source": "e1", "target": "e2", "type": "KNOWS"},
        ]
        
        scene = self.engine.create_network_graph(
            title="Test Graph",
            entities=entities,
            relationships=relationships,
        )
        
        assert scene is not None
        assert len(scene.nodes) == 2
        assert len(scene.edges) == 1
        assert scene.visualization_type == VisualizationType.NETWORK_GRAPH
    
    def test_create_3d_graph(self):
        """Test 3D graph creation."""
        entities = [
            {"id": "n1", "name": "Node 1"},
            {"id": "n2", "name": "Node 2"},
            {"id": "n3", "name": "Node 3"},
        ]
        
        scene = self.engine.create_3d_graph(
            title="3D Test",
            entities=entities,
            connections=[{"source": "n1", "target": "n2"}],
        )
        
        assert scene is not None
        assert len(scene.nodes) == 3
        assert len(scene.edges) == 1
    
    def test_create_timeline(self):
        """Test timeline creation."""
        events = [
            {"id": "ev1", "title": "Event 1"},
            {"id": "ev2", "title": "Event 2"},
            {"id": "ev3", "title": "Event 3"},
        ]
        
        scene = self.engine.create_timeline(
            title="Test Timeline",
            events=events,
        )
        
        assert scene is not None
        assert len(scene.nodes) == 3
        assert scene.visualization_type == VisualizationType.TIMELINE
    
    def test_create_heatmap(self):
        """Test heatmap creation."""
        data = {
            "Region A": 75,
            "Region B": 45,
            "Region C": 90,
        }
        
        scene = self.engine.create_heatmap(
            title="Risk Heatmap",
            data=data,
        )
        
        assert scene is not None
        assert len(scene.nodes) == 3
    
    def test_get_scene(self):
        """Test getting a scene."""
        entities = [{"id": "e1", "name": "Entity 1"}]
        scene = self.engine.create_network_graph("Test", entities, [])
        
        retrieved = self.engine.get_scene(scene.scene_id)
        assert retrieved is not None
        assert retrieved.scene_id == scene.scene_id


class TestFraudRingDiscovery:
    """Tests for FraudRingDiscovery."""
    
    def setup_method(self):
        self.discovery = FraudRingDiscovery()
    
    def test_discover_ring(self):
        """Test fraud ring discovery."""
        entities = [
            {"id": "m1", "name": "Mule 1", "type": "MULE_ACCOUNT"},
            {"id": "m2", "name": "Mule 2", "type": "MULE_ACCOUNT"},
        ]
        connections = [
            {"source": "m1", "target": "m2", "type": "TRANSFERS"},
        ]
        
        ring = self.discovery.discover_ring(entities, connections)
        
        assert ring is not None
        assert len(ring.members) == 2
        assert ring.ring_type in ["MULE_NETWORK", "GENERAL_FRAUD_RING"]
    
    def test_get_ring(self):
        """Test getting a ring."""
        entities = [{"id": "e1", "name": "Entity 1"}]
        ring = self.discovery.discover_ring(entities, [])
        
        retrieved = self.discovery.get_ring(ring.ring_id)
        assert retrieved is not None
        assert retrieved.ring_id == ring.ring_id
    
    def test_get_high_risk_rings(self):
        """Test getting high risk rings."""
        entities = [
            {"id": "e1", "name": "Entity 1", "type": "MULE_ACCOUNT"},
            {"id": "e2", "name": "Entity 2", "type": "MULE_ACCOUNT"},
        ]
        connections = [
            {"source": "e1", "target": "e2", "type": "TRANSFER"},
            {"source": "e2", "target": "e1", "type": "TRANSFER"},
        ]
        
        ring = self.discovery.discover_ring(entities, connections)
        ring.risk_score = 0.8
        
        high_risk = self.discovery.get_high_risk_rings(threshold=0.7)
        assert len(high_risk) >= 1
    
    def test_analyze_ring_connections(self):
        """Test ring connection analysis."""
        entities = [
            {"id": "a", "name": "A"},
            {"id": "b", "name": "B"},
            {"id": "c", "name": "C"},
        ]
        connections = [
            {"source": "a", "target": "b"},
            {"source": "b", "target": "c"},
        ]
        
        ring = self.discovery.discover_ring(entities, connections)
        analysis = self.discovery.analyze_ring_connections(ring.ring_id)
        
        assert "member_count" in analysis
        assert "connectivity_score" in analysis


class TestInvestigationManager:
    """Tests for InvestigationManager."""
    
    def setup_method(self):
        self.manager = InvestigationManager()
    
    def test_create_case(self):
        """Test case creation."""
        case = self.manager.create_case(
            title="Test Investigation",
            description="Test description",
            priority="HIGH",
        )
        
        assert case is not None
        assert case.title == "Test Investigation"
        assert case.priority == "HIGH"
    
    def test_get_case(self):
        """Test getting a case."""
        case = self.manager.create_case("Test", "Description")
        
        retrieved = self.manager.get_case(case.case_id)
        assert retrieved is not None
        assert retrieved.case_id == case.case_id
    
    def test_update_case(self):
        """Test updating a case."""
        case = self.manager.create_case("Test", "Description")
        
        success = self.manager.update_case(
            case.case_id,
            status=InvestigationStatus.CLOSED,
        )
        
        assert success is True
        updated = self.manager.get_case(case.case_id)
        assert updated.status == InvestigationStatus.CLOSED
    
    def test_add_timeline_event(self):
        """Test adding timeline event."""
        case = self.manager.create_case("Test", "Description")
        
        event = {
            "type": "ALERT",
            "title": "Suspicious Activity",
        }
        
        success = self.manager.add_timeline_event(case.case_id, event)
        assert success is True
        
        updated = self.manager.get_case(case.case_id)
        assert len(updated.timeline) == 1
    
    def test_get_active_cases(self):
        """Test getting active cases."""
        self.manager.create_case("Active 1", "Desc")
        self.manager.create_case("Active 2", "Desc")
        
        active = self.manager.get_active_cases()
        assert len(active) >= 2


class TestModels:
    """Tests for model classes."""
    
    def test_visualization_node_to_dict(self):
        """Test VisualizationNode serialization."""
        node = VisualizationNode(
            node_id="test-1",
            label="Test Node",
            node_type="ENTITY",
        )
        
        data = node.to_dict()
        assert data["node_id"] == "test-1"
        assert data["label"] == "Test Node"
    
    def test_investigation_case_to_dict(self):
        """Test InvestigationCase serialization."""
        case = InvestigationCase(
            case_id="case-1",
            title="Test Case",
            description="Test description",
        )
        
        data = case.to_dict()
        assert data["case_id"] == "case-1"
        assert data["title"] == "Test Case"
    
    def test_visualization_type_values(self):
        """Test VisualizationType enum."""
        assert VisualizationType.NETWORK_GRAPH.value == "NETWORK_GRAPH"
        assert VisualizationType.GRAPH_3D.value == "GRAPH_3D"
        assert len(VisualizationType) > 0
    
    def test_investigation_status_values(self):
        """Test InvestigationStatus enum."""
        assert InvestigationStatus.ACTIVE.value == "ACTIVE"
        assert InvestigationStatus.CLOSED.value == "CLOSED"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])