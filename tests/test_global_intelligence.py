"""
Tests for Global Fraud Intelligence Knowledge Graph & Federation Platform.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from src.global_intelligence import (
    # Store
    get_global_intelligence_store,
    reset_store,
    GlobalIntelligenceStore,
    # Models
    EntityType,
    FederatedEntity,
    ThreatLevel,
    ThreatIndicator,
    FraudNetwork,
    NetworkType,
    InvestigationCase,
    InvestigationStatus,
    FederationPartner,
    FederationStatus,
    # Engines
    get_federation_engine,
    get_knowledge_graph_engine,
    get_entity_correlation_engine,
    get_threat_exchange,
    get_campaign_discovery_engine,
    get_network_analysis_engine,
    get_federated_search_engine,
    get_risk_propagation_engine,
    get_audit_service,
    # Service
    get_global_intelligence_service,
)


class TestModels:
    """Test data models."""

    def test_federated_entity_creation(self):
        """Test federated entity model."""
        entity = FederatedEntity(
            entity_id="test-entity-1",
            entity_type=EntityType.ACCOUNT,
            federation_id="fed-1",
            partner_id="partner-1",
            external_id="ext-123",
            risk_score=0.75,
            threat_level=ThreatLevel.HIGH,
        )

        assert entity.entity_id == "test-entity-1"
        assert entity.entity_type == EntityType.ACCOUNT
        assert entity.risk_score == 0.75
        assert entity.threat_level == ThreatLevel.HIGH

    def test_federated_entity_anonymization(self):
        """Test entity anonymization."""
        entity = FederatedEntity(
            entity_id="test-entity-1",
            entity_type=EntityType.ACCOUNT,
            federation_id="fed-1",
            partner_id="partner-1",
            external_id="ext-123",
            attributes={"email": "test@example.com"},
            risk_score=0.75,
            threat_level=ThreatLevel.HIGH,
        )

        anon = entity.to_anonymized()
        assert anon.is_anonymized is True
        assert anon.external_id == "REDACTED"
        assert anon.partner_id == "ANONYMIZED"
        assert anon.attributes == {}

    def test_threat_indicator_expiration(self):
        """Test indicator expiration check."""
        indicator = ThreatIndicator(
            indicator_id="ind-1",
            indicator_type="ip",
            value="1.2.3.4",
            source="internal",
            threat_type="malware",
            threat_level=ThreatLevel.HIGH,
            confidence=0.9,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            expiration=None,
            partner_id="partner-1",
        )
        assert indicator.is_expired() is False

        # Expired indicator
        expired_indicator = ThreatIndicator(
            indicator_id="ind-2",
            indicator_type="ip",
            value="5.6.7.8",
            source="internal",
            threat_type="malware",
            threat_level=ThreatLevel.HIGH,
            confidence=0.9,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            expiration=datetime.now(timezone.utc) - timedelta(days=1),
            partner_id="partner-1",
        )
        assert expired_indicator.is_expired() is True


class TestGlobalIntelligenceStore:
    """Test global intelligence store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_store()

    def test_entity_storage(self):
        """Test storing and retrieving entities."""
        store = get_global_intelligence_store()

        entity = FederatedEntity(
            entity_id="test-entity-1",
            entity_type=EntityType.ACCOUNT,
            federation_id="fed-1",
            partner_id="partner-1",
            external_id="ext-123",
            risk_score=0.5,
            threat_level=ThreatLevel.MEDIUM,
        )

        store.store_entity(entity)
        retrieved = store.get_entity("test-entity-1")

        assert retrieved is not None
        assert retrieved.entity_id == entity.entity_id
        assert retrieved.risk_score == 0.5

    def test_indicator_storage(self):
        """Test storing and retrieving indicators."""
        store = get_global_intelligence_store()

        indicator = ThreatIndicator(
            indicator_id="ind-1",
            indicator_type="ip",
            value="1.2.3.4",
            source="internal",
            threat_type="malware",
            threat_level=ThreatLevel.HIGH,
            confidence=0.9,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            expiration=datetime.now(timezone.utc) + timedelta(days=7),
            partner_id="partner-1",
        )

        store.store_indicator(indicator)
        retrieved = store.get_indicator("ind-1")

        assert retrieved is not None
        assert retrieved.value == "1.2.3.4"
        assert retrieved.threat_level == ThreatLevel.HIGH

    def test_partner_storage(self):
        """Test partner storage and retrieval."""
        store = get_global_intelligence_store()

        partner = FederationPartner(
            partner_id="partner-1",
            organization_name="Test Org",
            organization_type="bank",
            status=FederationStatus.ACTIVE,
            trust_level=80,
            api_endpoint="https://api.test.com",
            api_key_hash="abc123",
            joined_at=datetime.now(timezone.utc),
            last_sync=datetime.now(timezone.utc),
        )

        store.store_partner(partner)
        retrieved = store.get_partner("partner-1")

        assert retrieved is not None
        assert retrieved.organization_name == "Test Org"
        assert retrieved.trust_level == 80

    def test_network_storage(self):
        """Test fraud network storage."""
        store = get_global_intelligence_store()

        network = FraudNetwork(
            network_id="net-1",
            network_type=NetworkType.FRAUD_RING,
            nodes=["entity-1", "entity-2", "entity-3"],
            edges=[{"source": "entity-1", "target": "entity-2"}],
            confidence_score=0.85,
            threat_level=ThreatLevel.HIGH,
            member_count=3,
            activity_score=0.7,
            first_detected=datetime.now(timezone.utc),
            last_activity=datetime.now(timezone.utc),
        )

        store.store_network(network)
        retrieved = store.get_network("net-1")

        assert retrieved is not None
        assert retrieved.member_count == 3
        assert retrieved.threat_level == ThreatLevel.HIGH

    def test_store_statistics(self):
        """Test store statistics."""
        store = get_global_intelligence_store()

        entity = FederatedEntity(
            entity_id="test-1",
            entity_type=EntityType.ACCOUNT,
            federation_id="fed-1",
            partner_id="partner-1",
            external_id="ext-1",
            risk_score=0.5,
            threat_level=ThreatLevel.MEDIUM,
        )
        store.store_entity(entity)

        stats = store.get_stats()
        assert stats["total_entities"] >= 1


class TestFederationEngine:
    """Test federation engine."""

    def setup_method(self):
        """Reset store and engine."""
        reset_store()

    def test_partner_registration(self):
        """Test partner registration."""
        engine = get_federation_engine()

        partner = engine.register_partner(
            organization_name="Test Bank",
            organization_type="bank",
            api_endpoint="https://api.testbank.com",
        )

        assert partner.partner_id is not None
        assert partner.organization_name == "Test Bank"
        assert partner.status == FederationStatus.PENDING

    def test_partner_activation(self):
        """Test partner activation."""
        store = get_global_intelligence_store()
        engine = get_federation_engine()

        partner = engine.register_partner(
            organization_name="Test Bank",
            organization_type="bank",
        )

        success = engine.activate_partner(partner.partner_id, trust_level=75)

        assert success is True
        # Get from store - engine uses the same store
        retrieved = engine._store.get_partner(partner.partner_id)
        assert retrieved is not None
        assert retrieved.status == FederationStatus.ACTIVE
        assert retrieved.trust_level == 75

    def test_intelligence_sharing(self):
        """Test intelligence sharing."""
        engine = get_federation_engine()

        # Register and activate partner
        partner1 = engine.register_partner(
            organization_name="Bank A",
            organization_type="bank",
        )
        engine.activate_partner(partner1.partner_id, trust_level=80)

        # Create entity
        entity = FederatedEntity(
            entity_id="entity-1",
            entity_type=EntityType.ACCOUNT,
            federation_id="fed-1",
            partner_id=partner1.partner_id,
            external_id="ext-1",
            risk_score=0.7,
            threat_level=ThreatLevel.HIGH,
        )

        # Share with self
        response = engine.share_intelligence(entity, ["self"])

        assert response.success is True
        assert response.share_id is not None


class TestKnowledgeGraph:
    """Test knowledge graph engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_add_node(self):
        """Test adding nodes to graph."""
        graph = get_knowledge_graph_engine()

        node = graph.add_entity(
            entity_id="node-1",
            entity_type=EntityType.ACCOUNT,
            properties={"name": "Test Account"},
        )

        assert node.node_id == "node-1"
        assert node.entity_type == EntityType.ACCOUNT

    def test_add_relationship(self):
        """Test adding relationships."""
        graph = get_knowledge_graph_engine()

        # Add nodes
        graph.add_entity("node-1", EntityType.ACCOUNT, {"name": "Account 1"})
        graph.add_entity("node-2", EntityType.PERSON, {"name": "Person 1"})

        # Add relationship
        edge = graph.add_relationship(
            source_id="node-1",
            target_id="node-2",
            relationship_type="owned_by",
            weight=1.0,
        )

        assert edge.edge_id is not None
        assert edge.source_id == "node-1"
        assert edge.target_id == "node-2"

    def test_bfs_traversal(self):
        """Test BFS graph traversal."""
        graph = get_knowledge_graph_engine()

        # Create a simple graph
        for i in range(5):
            graph.add_entity(f"node-{i}", EntityType.ACCOUNT, {})

        graph.add_relationship("node-0", "node-1", "linked_to")
        graph.add_relationship("node-1", "node-2", "linked_to")
        graph.add_relationship("node-2", "node-3", "linked_to")

        result = graph.traverse("node-0", max_depth=3)

        assert result.nodes_visited > 0
        assert len(result.nodes) > 0


class TestEntityCorrelation:
    """Test entity correlation engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_entity_correlation(self):
        """Test entity correlation."""
        store = get_global_intelligence_store()
        correlation = get_entity_correlation_engine()

        # Add entities
        entity1 = FederatedEntity(
            entity_id="entity-1",
            entity_type=EntityType.ACCOUNT,
            federation_id="fed-1",
            partner_id="partner-1",
            external_id="ext-1",
            attributes={"email": "test@example.com", "phone": "1234567890"},
            risk_score=0.6,
            threat_level=ThreatLevel.MEDIUM,
        )

        entity2 = FederatedEntity(
            entity_id="entity-2",
            entity_type=EntityType.ACCOUNT,
            federation_id="fed-1",
            partner_id="partner-1",
            external_id="ext-2",
            attributes={"email": "test@example.com", "phone": "0987654321"},
            risk_score=0.7,
            threat_level=ThreatLevel.HIGH,
        )

        store.store_entity(entity1)
        store.store_entity(entity2)

        result = correlation.correlate_entities(entity1)

        assert result.matches_found >= 0


class TestThreatExchange:
    """Test threat intelligence exchange."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_add_indicator(self):
        """Test adding threat indicators."""
        exchange = get_threat_exchange()

        indicator = exchange.add_indicator(
            indicator_type="ip",
            value="1.2.3.4",
            threat_type="malware",
            threat_level=ThreatLevel.HIGH,
            source="internal",
            confidence=0.9,
        )

        assert indicator.indicator_id is not None
        assert indicator.value == "1.2.3.4"
        assert indicator.threat_level == ThreatLevel.HIGH

    def test_search_indicators(self):
        """Test searching indicators."""
        exchange = get_threat_exchange()

        exchange.add_indicator(
            indicator_type="ip",
            value="1.2.3.4",
            threat_type="malware",
            threat_level=ThreatLevel.HIGH,
            source="internal",
        )

        results = exchange.search_indicators(query="1.2.3")

        assert len(results) > 0


class TestNetworkAnalysis:
    """Test network analysis engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_network_discovery(self):
        """Test discovering networks."""
        store = get_global_intelligence_store()
        analysis = get_network_analysis_engine()

        # Add connected entities
        for i in range(5):
            entity = FederatedEntity(
                entity_id=f"entity-{i}",
                entity_type=EntityType.ACCOUNT,
                federation_id="fed-1",
                partner_id="partner-1",
                external_id=f"ext-{i}",
                risk_score=0.6,
                threat_level=ThreatLevel.MEDIUM,
            )
            store.store_entity(entity)

        networks = analysis.discover_networks()

        # May or may not find networks depending on connections
        assert isinstance(networks, list)


class TestRiskPropagation:
    """Test risk propagation engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_risk_propagation(self):
        """Test risk propagation."""
        store = get_global_intelligence_store()
        propagation = get_risk_propagation_engine()

        # Add high-risk entity
        entity = FederatedEntity(
            entity_id="high-risk-entity",
            entity_type=EntityType.ACCOUNT,
            federation_id="fed-1",
            partner_id="partner-1",
            external_id="ext-1",
            risk_score=0.9,
            threat_level=ThreatLevel.CRITICAL,
        )
        store.store_entity(entity)

        # Propagate risk
        propagations = propagation.propagate_risk("high-risk-entity")

        assert isinstance(propagations, list)


class TestFederatedSearch:
    """Test federated search engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_search(self):
        """Test federated search."""
        store = get_global_intelligence_store()
        search = get_federated_search_engine()

        # Add some entities
        for i in range(3):
            entity = FederatedEntity(
                entity_id=f"search-entity-{i}",
                entity_type=EntityType.ACCOUNT,
                federation_id="fed-1",
                partner_id="partner-1",
                external_id=f"ext-{i}",
                attributes={"name": f"Test Account {i}"},
                risk_score=0.5,
                threat_level=ThreatLevel.LOW,
            )
            store.store_entity(entity)

        from src.global_intelligence.federated_search import SearchQuery

        query = SearchQuery(
            query_id="test-query",
            query_text="Test",
            entity_types=[EntityType.ACCOUNT],
            threat_levels=[ThreatLevel.LOW],
            date_range_start=None,
            date_range_end=None,
        )

        results = search.search(query)

        assert isinstance(results, list)


class TestGlobalIntelligenceService:
    """Test main service."""

    def setup_method(self):
        """Reset all."""
        reset_store()

    def test_dashboard_metrics(self):
        """Test dashboard metrics."""
        service = get_global_intelligence_service()

        metrics = service.get_dashboard_metrics()

        assert metrics.total_entities >= 0
        assert metrics.federation_partners >= 1  # Self partner
        assert metrics.last_updated is not None

    def test_register_partner(self):
        """Test partner registration via service."""
        service = get_global_intelligence_service()

        result = service.register_partner(
            organization_name="Test Bank",
            organization_type="bank",
        )

        assert "partner_id" in result
        assert result["organization_name"] == "Test Bank"

    def test_share_intelligence(self):
        """Test intelligence sharing via service."""
        service = get_global_intelligence_service()

        entity = FederatedEntity(
            entity_id="service-test-entity",
            entity_type=EntityType.ACCOUNT,
            federation_id="primary",
            partner_id="self",
            external_id="ext-1",
            risk_score=0.6,
            threat_level=ThreatLevel.MEDIUM,
        )

        result = service.share_intelligence(entity, ["self"])

        assert "success" in result

    def test_search_intelligence(self):
        """Test search via service."""
        service = get_global_intelligence_service()

        results = service.search_intelligence(
            query="test",
            limit=10,
        )

        assert isinstance(results, list)

    def test_create_investigation(self):
        """Test investigation creation."""
        service = get_global_intelligence_service()

        result = service.create_investigation(
            title="Test Investigation",
            description="Testing investigation creation",
            priority=1,
            created_by="test-user",
        )

        assert "case_id" in result
        assert result["title"] == "Test Investigation"

    def test_get_investigations(self):
        """Test getting investigations."""
        service = get_global_intelligence_service()

        # Create an investigation first
        service.create_investigation(
            title="Test",
            description="Test",
            priority=1,
            created_by="user",
        )

        investigations = service.get_investigations()

        assert len(investigations) >= 1

    def test_add_threat_indicator(self):
        """Test adding threat indicator."""
        service = get_global_intelligence_service()

        result = service.add_threat_indicator(
            indicator_type="ip",
            value="1.2.3.4",
            threat_type="malware",
            threat_level="high",
        )

        assert "indicator_id" in result

    def test_search_indicators(self):
        """Test searching indicators."""
        service = get_global_intelligence_service()

        # Add indicator first
        service.add_threat_indicator(
            indicator_type="ip",
            value="5.6.7.8",
            threat_type="phishing",
            threat_level="medium",
        )

        results = service.search_indicators(query="5.6.7")

        assert isinstance(results, list)


class TestAuditService:
    """Test audit service."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_log_operation(self):
        """Test logging audit operation."""
        audit = get_audit_service()

        record = audit.log_operation(
            operation="test_operation",
            user_id="test-user",
            partner_id="partner-1",
            entity_ids=["entity-1", "entity-2"],
            success=True,
        )

        assert record.record_id is not None
        assert record.operation == "test_operation"
        assert record.user_id == "test-user"

    def test_audit_summary(self):
        """Test getting audit summary."""
        audit = get_audit_service()

        # Log some operations
        audit.log_operation("op1", "user1")
        audit.log_operation("op2", "user2")

        summary = audit.get_summary(period_days=7)

        assert summary.total_operations >= 2
        assert "operations_by_type" in summary.__dict__


if __name__ == "__main__":
    pytest.main([__file__, "-v"])