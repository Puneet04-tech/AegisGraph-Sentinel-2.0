"""
Tests for Security Intelligence Mesh.
"""

import asyncio
import pytest

from src.security_mesh import (
    Intelligence,
    IntelligenceType,
    KnowledgeGraphEntry,
    MeshNode,
    NodeStatus,
    NodeType,
    ShareLevel,
    SecurityMeshStore,
    get_mesh_store,
    reset_mesh_store,
    MeshController,
    IntelligenceRouter,
    DecisionEngine,
    FederationEngine,
    SecurityOrchestrator,
    SecurityMeshService,
)


class TestModels:
    """Test data models."""

    def test_mesh_node_creation(self):
        """Test mesh node creation."""
        node = MeshNode(
            node_id="node-1",
            node_type=NodeType.FRAUD,
            name="Fraud Detection Node",
            endpoint="https://fraud.internal/api",
        )
        assert node.node_id == "node-1"
        assert node.node_type == NodeType.FRAUD
        assert node.status == NodeStatus.ACTIVE

    def test_intelligence_creation(self):
        """Test intelligence creation."""
        intel = Intelligence(
            intel_id="intel-1",
            source_node="node-1",
            intelligence_type=IntelligenceType.THREAT,
            title="Test Threat",
            description="Test description",
        )
        assert intel.intel_id == "intel-1"
        assert intel.confidence == 0.8


class TestStore:
    """Test mesh store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_mesh_store()
        self.store = get_mesh_store()

    def test_register_node(self):
        """Test registering a node."""
        node = MeshNode(
            node_id="node-1",
            node_type=NodeType.FRAUD,
            name="Test Node",
            endpoint="http://test.local",
        )
        self.store.register_node(node)
        
        retrieved = self.store.get_node("node-1")
        assert retrieved is not None
        assert retrieved.name == "Test Node"

    def test_store_intelligence(self):
        """Test storing intelligence."""
        intel = Intelligence(
            intel_id="intel-1",
            source_node="node-1",
            intelligence_type=IntelligenceType.THREAT,
            title="Test",
            description="Test",
        )
        self.store.store_intelligence(intel)
        
        retrieved = self.store.get_intelligence("intel-1")
        assert retrieved is not None


class TestController:
    """Test mesh controller."""

    def setup_method(self):
        """Reset store before each test."""
        reset_mesh_store()
        self.controller = MeshController()

    def test_register_node(self):
        """Test registering a node."""
        node = self.controller.register_node(
            node_type="fraud",
            name="Fraud Node",
            endpoint="http://fraud.local",
        )
        
        assert node.node_id is not None
        assert node.node_type == NodeType.FRAUD

    def test_heartbeat(self):
        """Test node heartbeat."""
        node = self.controller.register_node(
            node_type="aml",
            name="AML Node",
            endpoint="http://aml.local",
        )
        
        result = self.controller.heartbeat(node.node_id)
        assert result is True

    def test_get_all_nodes(self):
        """Test getting all nodes."""
        self.controller.register_node("fraud", "Node 1", "http://1.local")
        self.controller.register_node("aml", "Node 2", "http://2.local")
        
        nodes = self.controller.get_all_nodes()
        assert len(nodes) >= 2


class TestRouter:
    """Test intelligence router."""

    def setup_method(self):
        """Reset store before each test."""
        reset_mesh_store()
        self.router = IntelligenceRouter()

    def test_share_intelligence(self):
        """Test sharing intelligence."""
        intel = self.router.share_intelligence(
            source_node="node-1",
            intelligence_type="threat",
            title="New Threat",
            description="A new threat detected",
            confidence=0.9,
        )
        
        assert intel.intel_id is not None

    def test_search_intelligence(self):
        """Test searching intelligence."""
        self.router.share_intelligence(
            source_node="node-1",
            intelligence_type="threat",
            title="Fraud Campaign",
            description="Fraud campaign detected",
        )
        
        results = self.router.search_intelligence("fraud")
        assert len(results) >= 1


class TestDecisionEngine:
    """Test decision engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_mesh_store()
        self.engine = DecisionEngine()

    def test_evaluate_intelligence(self):
        """Test evaluating intelligence."""
        intel = Intelligence(
            intel_id="intel-1",
            source_node="node-1",
            intelligence_type=IntelligenceType.THREAT,
            title="Critical Threat",
            description="Critical threat detected",
            confidence=0.9,
        )
        
        decisions = self.engine.evaluate_intelligence(intel)
        assert len(decisions) >= 1

    def test_create_task(self):
        """Test creating a task."""
        task = self.engine.create_task(
            task_type="investigation",
            source_node="node-1",
            parameters={"priority": 1},
        )
        
        assert task.task_id is not None


class TestFederationEngine:
    """Test federation engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_mesh_store()
        self.engine = FederationEngine()

    def test_add_knowledge_entry(self):
        """Test adding knowledge entry."""
        entry = self.engine.add_knowledge_entry(
            entity_type="account",
            entity_id="acc-123",
            attributes={"risk_score": 0.8},
            source_node="fraud",
        )
        
        assert entry.entry_id is not None

    def test_get_cross_domain_insights(self):
        """Test getting cross-domain insights."""
        insights = self.engine.get_cross_domain_insights()
        assert "domain_counts" in insights


class TestOrchestrator:
    """Test security orchestrator."""

    def setup_method(self):
        """Reset store before each test."""
        reset_mesh_store()
        self.orchestrator = SecurityOrchestrator()

    def test_execute_automated_action(self):
        """Test executing automated action."""
        node = MeshNode(
            node_id="node-1",
            node_type=NodeType.FRAUD,
            name="Test Node",
            endpoint="http://test.local",
        )
        get_mesh_store().register_node(node)
        
        result = self.orchestrator.execute_automated_action(
            action_type="block_ip",
            target_node="node-1",
            parameters={"ip": "192.168.1.1"},
        )
        
        assert result["success"] is True


class TestSecurityMeshService:
    """Test main service."""

    def setup_method(self):
        """Reset store before each test."""
        reset_mesh_store()
        self.service = SecurityMeshService()

    def test_register(self):
        """Test registering a node."""
        result = asyncio.run(self.service.register(
            node_type="fraud",
            name="Test Node",
            endpoint="http://test.local",
        ))
        
        assert "node_id" in result

    def test_share(self):
        """Test sharing intelligence."""
        result = asyncio.run(self.service.share(
            source_node="node-1",
            intelligence_type="threat",
            title="Test Threat",
            description="A test threat",
            confidence=0.9,
        ))
        
        assert "intel_id" in result

    def test_get_dashboard(self):
        """Test getting dashboard."""
        result = asyncio.run(self.service.get_dashboard())
        
        assert "total_nodes" in result

    def test_get_health(self):
        """Test getting health."""
        result = asyncio.run(self.service.get_health())
        
        assert "status" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])