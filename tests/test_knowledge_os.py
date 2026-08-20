"""
Tests for Knowledge Operating System Module
"""
import pytest
from datetime import datetime, timezone

from src.knowledge_os import (
    KnowledgeEngine,
    get_knowledge_engine,
    KnowledgeGraphManager,
    KnowledgeRetrievalEngine,
    KnowledgeEntry,
    KnowledgeType,
    KnowledgeStatus,
    AccessLevel,
)


class TestKnowledgeEngine:
    """Tests for KnowledgeEngine."""
    
    def setup_method(self):
        self.engine = KnowledgeEngine()
    
    def test_initialization(self):
        """Test engine initialization."""
        assert len(self.engine.entries) > 0
    
    def test_store_entry(self):
        """Test storing an entry."""
        entry_id = self.engine.store_entry(
            title="Test Entry",
            content="Test content",
            knowledge_type=KnowledgeType.FRAUD_PATTERN,
            created_by="admin",
        )
        
        assert entry_id is not None
        assert self.engine.get_entry(entry_id) is not None
    
    def test_get_entry(self):
        """Test getting an entry."""
        entry_id = self.engine.store_entry(
            title="Get Test",
            content="Content",
            knowledge_type=KnowledgeType.THREAT_INTEL,
        )
        
        entry = self.engine.get_entry(entry_id)
        assert entry is not None
        assert entry.title == "Get Test"
    
    def test_update_entry(self):
        """Test updating an entry."""
        entry_id = self.engine.store_entry(
            title="Update Test",
            content="Original",
            knowledge_type=KnowledgeType.AML_INDICATOR,
        )
        
        success = self.engine.update_entry(
            entry_id=entry_id,
            status=KnowledgeStatus.APPROVED,
            content="Updated",
        )
        
        assert success is True
        entry = self.engine.get_entry(entry_id)
        assert entry.status == KnowledgeStatus.APPROVED
    
    def test_search(self):
        """Test searching entries."""
        self.engine.store_entry(
            title="Mule Account Detection",
            content="Detection patterns",
            knowledge_type=KnowledgeType.FRAUD_PATTERN,
            tags=["mule", "detection"],
        )
        
        results = self.engine.search("mule")
        assert len(results) >= 1
    
    def test_add_relationship(self):
        """Test adding relationships."""
        id1 = self.engine.store_entry("Entry 1", "Content 1", KnowledgeType.FRAUD_PATTERN)
        id2 = self.engine.store_entry("Entry 2", "Content 2", KnowledgeType.THREAT_INTEL)
        
        success = self.engine.add_relationship(id1, id2)
        assert success is True
        
        related = self.engine.get_related(id1)
        assert len(related) >= 1
    
    def test_get_related(self):
        """Test getting related entries."""
        id1 = self.engine.store_entry("Related Test 1", "Content", KnowledgeType.FRAUD_PATTERN)
        id2 = self.engine.store_entry("Related Test 2", "Content", KnowledgeType.THREAT_INTEL)
        
        self.engine.add_relationship(id1, id2)
        
        related = self.engine.get_related(id1)
        assert len(related) >= 1

    def test_get_entry_above_clearance_is_hidden(self):
        """Test that an entry above the caller's clearance is treated as not found."""
        entry_id = self.engine.store_entry(
            "Classified Entry", "Secret content", KnowledgeType.THREAT_INTEL,
            access_level=AccessLevel.TOP_SECRET,
        )
        
        assert self.engine.get_entry(entry_id, clearance=AccessLevel.RESTRICTED) is None
        assert self.engine.get_entry(entry_id, clearance=AccessLevel.TOP_SECRET) is not None
        assert self.engine.get_entry(entry_id) is not None
    
    def test_search_excludes_entries_above_clearance(self):
        """Test that search results are filtered by clearance."""
        self.engine.store_entry(
            "Classified Search Target", "Secret content", KnowledgeType.THREAT_INTEL,
            access_level=AccessLevel.TOP_SECRET,
        )
        
        results = self.engine.search("Classified Search Target", clearance=AccessLevel.RESTRICTED)
        assert len(results) == 0
        
        results = self.engine.search("Classified Search Target", clearance=AccessLevel.TOP_SECRET)
        assert len(results) == 1
    
    def test_get_related_excludes_entries_above_clearance(self):
        """Test that related entries above clearance are excluded."""
        id1 = self.engine.store_entry("Clearance Related 1", "Content", KnowledgeType.FRAUD_PATTERN)
        id2 = self.engine.store_entry(
            "Clearance Related 2", "Content", KnowledgeType.THREAT_INTEL,
            access_level=AccessLevel.TOP_SECRET,
        )
        self.engine.add_relationship(id1, id2)
        
        assert self.engine.get_related(id1, clearance=AccessLevel.RESTRICTED) == []
        assert len(self.engine.get_related(id1, clearance=AccessLevel.TOP_SECRET)) == 1


class TestKnowledgeGraphManager:
    """Tests for KnowledgeGraphManager."""
    
    def setup_method(self):
        self.engine = KnowledgeEngine()
        self.manager = KnowledgeGraphManager(self.engine)
    
    def test_create_graph(self):
        """Test creating a graph."""
        graph_id = self.manager.create_graph("Test Graph")
        
        assert graph_id is not None
        assert self.manager.get_graph(graph_id) is not None
    
    def test_get_graph(self):
        """Test getting a graph."""
        graph_id = self.manager.create_graph("Get Test")
        
        graph = self.manager.get_graph(graph_id)
        assert graph is not None
        assert graph.graph_id == graph_id
    
    def test_add_node(self):
        """Test adding a node."""
        graph_id = self.manager.create_graph("Node Test")
        
        success = self.manager.add_node(
            graph_id=graph_id,
            node_id="node-1",
            label="Test Node",
            node_type="ENTITY",
        )
        
        assert success is True
        graph = self.manager.get_graph(graph_id)
        assert len(graph.nodes) >= 1
    
    def test_correlate_entries(self):
        """Test correlating entries."""
        id1 = self.engine.store_entry(
            "Correlation Test 1",
            "Content",
            KnowledgeType.FRAUD_PATTERN,
            tags=["fraud", "detection"],
        )
        id2 = self.engine.store_entry(
            "Correlation Test 2",
            "Content",
            KnowledgeType.FRAUD_PATTERN,
            tags=["fraud", "pattern"],
        )
        
        correlations = self.manager.correlate_entries([id1, id2])
        assert isinstance(correlations, list)


class TestKnowledgeRetrievalEngine:
    """Tests for KnowledgeRetrievalEngine."""
    
    def setup_method(self):
        self.engine = KnowledgeEngine()
        self.retrieval = KnowledgeRetrievalEngine(self.engine)
    
    def test_retrieve(self):
        """Test retrieving knowledge."""
        results = self.retrieval.retrieve(
            query="fraud detection",
            context={"domain": "fraud"},
            max_results=5,
        )
        
        assert isinstance(results, list)
    
    def test_get_recommendations(self):
        """Test getting recommendations."""
        recs = self.retrieval.get_recommendations(
            user_id="user-1",
            context={"domain": "fraud", "query": "detection"},
            limit=5,
        )
        
        assert isinstance(recs, list)


class TestModels:
    """Tests for model classes."""
    
    def test_knowledge_entry_to_dict(self):
        """Test KnowledgeEntry serialization."""
        entry = KnowledgeEntry(
            entry_id="test-1",
            title="Test Entry",
            content="Test content",
            knowledge_type=KnowledgeType.FRAUD_PATTERN,
        )
        
        data = entry.to_dict()
        assert data["entry_id"] == "test-1"
        assert data["knowledge_type"] == "FRAUD_PATTERN"
    
    def test_knowledge_type_values(self):
        """Test KnowledgeType enum."""
        assert KnowledgeType.FRAUD_PATTERN.value == "FRAUD_PATTERN"
        assert KnowledgeType.THREAT_INTEL.value == "THREAT_INTEL"
        assert len(KnowledgeType) > 0
    
    def test_access_level_values(self):
        """Test AccessLevel enum."""
        assert AccessLevel.PUBLIC.value == "PUBLIC"
        assert AccessLevel.TOP_SECRET.value == "TOP_SECRET"
        assert len(AccessLevel) > 0


class TestClearanceByRole:
    """Tests for the Role -> AccessLevel clearance mapping used by the routes."""
    
    def test_every_role_has_a_clearance(self):
        """Test that no role is left unmapped."""
        from src.api.security import Role
        from src.api.knowledge_routes import CLEARANCE_BY_ROLE
        
        for role in Role:
            assert role in CLEARANCE_BY_ROLE
    
    def test_super_admin_can_see_top_secret(self):
        """Test that SUPER_ADMIN's clearance covers the most sensitive tier."""
        from src.api.security import Role
        from src.api.knowledge_routes import CLEARANCE_BY_ROLE
        
        assert CLEARANCE_BY_ROLE[Role.SUPER_ADMIN] == AccessLevel.TOP_SECRET
    
    def test_analyst_cannot_see_confidential(self):
        """Test that the baseline ANALYST role does not reach CONFIDENTIAL entries."""
        from src.api.security import Role
        from src.api.knowledge_routes import CLEARANCE_BY_ROLE
        from src.knowledge_os import is_within_clearance
        
        entry = KnowledgeEntry(
            entry_id="test-confidential",
            title="Confidential Entry",
            content="Content",
            knowledge_type=KnowledgeType.THREAT_INTEL,
            access_level=AccessLevel.CONFIDENTIAL,
        )
        assert not is_within_clearance(entry, CLEARANCE_BY_ROLE[Role.ANALYST])
        assert is_within_clearance(entry, CLEARANCE_BY_ROLE[Role.ADMIN])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])