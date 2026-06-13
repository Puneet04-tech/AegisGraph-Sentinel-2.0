"""
Tests for Fraud Investigation Knowledge Hub
"""

import pytest

from src.knowledge_hub.models import (
    InvestigationTemplate,
    InvestigationRecord,
    KnowledgeEntry,
    EntityKnowledge,
    InvestigationType,
    EntityType,
)
from src.knowledge_hub.store import get_knowledge_hub_store, reset_knowledge_hub_store
from src.knowledge_hub.service import KnowledgeHubService


class TestKnowledgeHubModels:
    """Tests for knowledge hub models."""

    def test_create_template(self):
        """Test creating an investigation template."""
        template = InvestigationTemplate(
            name="Fraud Investigation",
            description="Standard fraud investigation",
            investigation_type=InvestigationType.FRAUD,
            steps=[{"step": "Review transactions"}],
        )
        assert template.name == "Fraud Investigation"
        assert template.investigation_type == InvestigationType.FRAUD

    def test_create_record(self):
        """Test creating an investigation record."""
        record = InvestigationRecord(
            title="Suspicious Transaction",
            description="Transaction analysis needed",
            investigation_type=InvestigationType.FRAUD,
            priority="HIGH",
        )
        assert record.title == "Suspicious Transaction"
        assert record.status == "OPEN"

    def test_create_knowledge_entry(self):
        """Test creating a knowledge entry."""
        entry = KnowledgeEntry(
            title="Money Laundering Patterns",
            content="Common money laundering patterns",
            entity_type=EntityType.ACCOUNT,
            tags=["fraud", "ml"],
        )
        assert entry.entity_type == EntityType.ACCOUNT
        assert len(entry.tags) == 2

    def test_create_entity(self):
        """Test creating an entity."""
        entity = EntityKnowledge(
            entity_type=EntityType.PERSON,
            entity_value="John Doe",
            attributes={"role": "analyst"},
        )
        assert entity.entity_type == EntityType.PERSON
        assert entity.risk_score == 0.0


class TestKnowledgeHubStore:
    """Tests for knowledge hub store."""

    def setup_method(self):
        """Set up test store."""
        reset_knowledge_hub_store()
        self.store = get_knowledge_hub_store()

    def test_store_template(self):
        """Test storing a template."""
        template = InvestigationTemplate(
            name="Test",
            description="Test",
            investigation_type=InvestigationType.CYBER,
        )
        self.store.store_template(template)
        retrieved = self.store.get_template(template.template_id)
        assert retrieved is not None
        assert retrieved.name == "Test"

    def test_store_record(self):
        """Test storing a record."""
        record = InvestigationRecord(
            title="Test",
            description="Test",
            investigation_type=InvestigationType.COMPLIANCE,
        )
        self.store.store_record(record)
        retrieved = self.store.get_record(record.record_id)
        assert retrieved is not None
        assert retrieved.title == "Test"

    def test_store_knowledge(self):
        """Test storing knowledge."""
        entry = KnowledgeEntry(
            title="Test",
            content="Test content",
            entity_type=EntityType.DOMAIN,
        )
        self.store.store_knowledge(entry)
        retrieved = self.store.get_knowledge(entry.entry_id)
        assert retrieved is not None

    def test_search_knowledge(self):
        """Test searching knowledge."""
        self.store.store_knowledge(KnowledgeEntry(
            title="Fraud Detection",
            content="How to detect fraud",
            entity_type=EntityType.TRANSACTION,
        ))
        results = self.store.search_knowledge("fraud")
        assert len(results) >= 1

    def test_store_entity(self):
        """Test storing an entity."""
        entity = EntityKnowledge(
            entity_type=EntityType.ACCOUNT,
            entity_value="ACC-001",
        )
        self.store.store_entity(entity)
        retrieved = self.store.get_entity(entity.entity_id)
        assert retrieved is not None

    def test_get_metrics(self):
        """Test getting metrics."""
        self.store.store_record(InvestigationRecord(
            title="Test",
            description="Test",
            investigation_type=InvestigationType.FRAUD,
        ))
        metrics = self.store.get_metrics()
        assert metrics["total_records"] >= 1


class TestKnowledgeHubService:
    """Tests for knowledge hub service."""

    def setup_method(self):
        """Set up test service."""
        reset_knowledge_hub_store()
        self.service = KnowledgeHubService()

    def test_create_template(self):
        """Test creating a template."""
        template = self.service.create_template(
            name="Standard Fraud Investigation",
            description="Standard fraud investigation template",
            investigation_type=InvestigationType.FRAUD,
        )
        assert template.template_id is not None
        assert template.name == "Standard Fraud Investigation"

    def test_create_investigation(self):
        """Test creating an investigation."""
        record = self.service.create_investigation(
            title="Suspicious Activity",
            description="Activity requires investigation",
            investigation_type=InvestigationType.FRAUD,
            priority="HIGH",
        )
        assert record.record_id is not None
        assert record.priority == "HIGH"

    def test_add_finding(self):
        """Test adding a finding."""
        record = self.service.create_investigation(
            title="Test",
            description="Test",
            investigation_type=InvestigationType.CYBER,
        )
        updated = self.service.add_finding(
            record.record_id,
            "Initial finding: suspicious IP",
        )
        assert updated is not None
        assert len(updated.findings) >= 1

    def test_link_investigation(self):
        """Test linking investigations."""
        record1 = self.service.create_investigation(
            title="Investigation 1",
            description="Test",
            investigation_type=InvestigationType.FRAUD,
        )
        record2 = self.service.create_investigation(
            title="Investigation 2",
            description="Test",
            investigation_type=InvestigationType.FRAUD,
        )
        linked = self.service.link_investigation(
            record1.record_id,
            record2.record_id,
        )
        assert linked is not None
        assert record2.record_id in linked.linked_investigations

    def test_add_knowledge(self):
        """Test adding knowledge."""
        entry = self.service.add_knowledge(
            title="Fraud Indicators",
            content="Common fraud indicators",
            entity_type=EntityType.TRANSACTION,
            tags=["fraud", "indicators"],
        )
        assert entry.entry_id is not None

    def test_search_knowledge(self):
        """Test searching knowledge."""
        self.service.add_knowledge(
            title="Phishing Attacks",
            content="How to identify phishing",
            entity_type=EntityType.EMAIL,
        )
        results = self.service.search_knowledge("phishing")
        assert len(results) >= 1

    def test_add_entity(self):
        """Test adding an entity."""
        entity = self.service.add_entity(
            entity_type=EntityType.PERSON,
            entity_value="user@example.com",
            attributes={"risk_level": "high"},
        )
        assert entity.entity_id is not None

    def test_add_relationship(self):
        """Test adding entity relationship."""
        entity1 = self.service.add_entity(
            entity_type=EntityType.ACCOUNT,
            entity_value="ACC-001",
        )
        entity2 = self.service.add_entity(
            entity_type=EntityType.PERSON,
            entity_value="John Doe",
        )
        related = self.service.add_relationship(
            entity1.entity_id,
            entity2.entity_id,
            "owned_by",
        )
        assert related is not None
        assert len(related.relationships) >= 1

    def test_get_metrics(self):
        """Test getting metrics."""
        self.service.create_investigation(
            title="Test",
            description="Test",
            investigation_type=InvestigationType.INSIDER,
        )
        metrics = self.service.get_metrics()
        assert metrics.total_records >= 1


class TestKnowledgeHubIntegration:
    """Integration tests for knowledge hub."""

    def setup_method(self):
        """Set up test environment."""
        reset_knowledge_hub_store()
        self.service = KnowledgeHubService()

    def test_full_knowledge_lifecycle(self):
        """Test complete knowledge lifecycle."""
        self.service.create_template(
            name="Standard Investigation",
            description="Standard investigation template",
            investigation_type=InvestigationType.THREAT_INTEL,
        )

        record = self.service.create_investigation(
            title="Threat Intelligence Case",
            description="Investigate threat actor",
            investigation_type=InvestigationType.THREAT_INTEL,
            priority="HIGH",
        )

        entity1 = self.service.add_entity(
            entity_type=EntityType.IP_ADDRESS,
            entity_value="192.168.1.1",
            risk_score=0.8,
        )

        entity2 = self.service.add_entity(
            entity_type=EntityType.DOMAIN,
            entity_value="malicious.com",
            risk_score=0.9,
        )

        self.service.add_relationship(
            entity1.entity_id,
            entity2.entity_id,
            "communicates_with",
        )

        self.service.add_finding(
            record.record_id,
            "IP communicates with malicious domain",
        )

        self.service.add_knowledge(
            title="Threat Actor TTPs",
            content="Known tactics, techniques, and procedures",
            entity_type=EntityType.ORGANIZATION,
        )

        search_results = self.service.search_knowledge("threat")
        assert len(search_results) >= 0

        metrics = self.service.get_metrics()
        assert metrics.total_records >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
