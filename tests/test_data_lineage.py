"""
Tests for Data Lineage & Provenance Platform
"""

import pytest
import threading
import time

from src.data_lineage.models import (
    DataRecord,
    LineageNode,
    LineageEdge,
    SourceAttribution,
    LineageQuery,
    RecordType,
    SourceType,
    TrustLevel,
    ImpactLevel,
)
from src.data_lineage.store import get_lineage_store, reset_lineage_store
from src.data_lineage.service import get_lineage_service, reset_lineage_service


class TestLineageModels:
    """Tests for lineage data models."""

    def test_create_data_record(self):
        """Test creating a data record."""
        record = DataRecord(
            record_type=RecordType.INTELLIGENCE,
            data={"indicator": "malware.exe", "type": "file_hash"},
            created_by="test",
        )
        assert record.record_id is not None
        assert record.record_type == RecordType.INTELLIGENCE
        assert record.data["indicator"] == "malware.exe"
        assert record.is_active is True
        assert record.version == 1

    def test_source_attribution(self):
        """Test source attribution model."""
        source = SourceAttribution(
            source_id="src_001",
            source_type=SourceType.EXTERNAL_FEED,
            source_name="Threat Intel Feed",
            trust_level=TrustLevel.HIGHLY_TRUSTED,
        )
        assert source.source_id == "src_001"
        assert source.trust_level == TrustLevel.HIGHLY_TRUSTED
        assert source.ingestion_timestamp is not None

    def test_lineage_node(self):
        """Test lineage node creation."""
        node = LineageNode(
            record_id="rec_001",
            record_type=RecordType.THREAT_INDICATOR,
            label="Test Node",
            is_root=True,
        )
        assert node.node_id is not None
        assert node.is_root is True
        assert node.version == 1

    def test_lineage_edge(self):
        """Test lineage edge creation."""
        edge = LineageEdge(
            source_node_id="node_001",
            target_node_id="node_002",
            relationship_type="derived_from",
            impact_level=ImpactLevel.HIGH,
        )
        assert edge.edge_id is not None
        assert edge.impact_level == ImpactLevel.HIGH

    def test_record_to_dict(self):
        """Test serialization of data record."""
        record = DataRecord(
            record_type=RecordType.FRAUD_SIGNAL,
            data={"score": 0.95},
            tags=["fraud", "high-risk"],
        )
        data = record.to_dict()
        assert data["record_type"] == "fraud_signal"
        assert data["data"]["score"] == 0.95
        assert "fraud" in data["tags"]


class TestLineageStore:
    """Tests for lineage store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_lineage_store()

    def test_store_and_retrieve_record(self):
        """Test storing and retrieving a record."""
        store = get_lineage_store()
        record = DataRecord(
            record_type=RecordType.INVESTIGATION,
            data={"case_id": "INV-001"},
        )
        store.store_record(record)

        retrieved = store.get_record(record.record_id)
        assert retrieved is not None
        assert retrieved.record_id == record.record_id
        assert retrieved.data["case_id"] == "INV-001"

    def test_cache_hit(self):
        """Test LRU cache behavior."""
        store = get_lineage_store()
        record = DataRecord(record_type=RecordType.INTELLIGENCE, data={})
        store.store_record(record)

        # First access - cache miss
        retrieved = store.get_record(record.record_id)
        assert retrieved is not None

    def test_store_node(self):
        """Test storing a lineage node."""
        store = get_lineage_store()
        node = LineageNode(
            record_id="rec_001",
            record_type=RecordType.INTELLIGENCE,
            label="Test",
        )
        store.store_node(node)

        retrieved = store.get_node(node.node_id)
        assert retrieved is not None
        assert retrieved.label == "Test"

    def test_store_edge(self):
        """Test storing a lineage edge."""
        store = get_lineage_store()
        edge = LineageEdge(
            source_node_id="node_001",
            target_node_id="node_002",
            relationship_type="depends_on",
        )
        store.store_edge(edge)

        retrieved = store.get_edge(edge.edge_id)
        assert retrieved is not None
        assert retrieved.relationship_type == "depends_on"

    def test_query_records_by_type(self):
        """Test querying records by type."""
        store = get_lineage_store()
        for i in range(5):
            record = DataRecord(
                record_type=RecordType.THREAT_INDICATOR if i % 2 == 0 else RecordType.FRAUD_SIGNAL,
                data={"index": i},
            )
            store.store_record(record)

        threat_records = store.get_records_by_type(RecordType.THREAT_INDICATOR)
        assert len(threat_records) == 3

    def test_get_connected_nodes(self):
        """Test getting connected nodes."""
        store = get_lineage_store()
        node1 = LineageNode(record_id="rec_001", record_type=RecordType.INTELLIGENCE, label="Node 1")
        node2 = LineageNode(record_id="rec_002", record_type=RecordType.INTELLIGENCE, label="Node 2")
        store.store_node(node1)
        store.store_node(node2)

        edge = LineageEdge(
            source_node_id=node1.node_id,
            target_node_id=node2.node_id,
            relationship_type="linked",
        )
        store.store_edge(edge)

        connected = store.get_connected_nodes(node1.node_id)
        assert len(connected) == 1
        assert connected[0].node_id == node2.node_id

    def test_get_stats(self):
        """Test getting lineage statistics."""
        store = get_lineage_store()
        for i in range(3):
            record = DataRecord(record_type=RecordType.INTELLIGENCE, data={})
            store.store_record(record)

        stats = store.get_stats()
        assert stats.total_records == 3
        assert stats.total_nodes == 0  # No nodes stored separately

    def test_clear_store(self):
        """Test clearing the store."""
        store = get_lineage_store()
        record = DataRecord(record_type=RecordType.INTELLIGENCE, data={})
        store.store_record(record)

        store.clear()
        stats = store.get_stats()
        assert stats.total_records == 0


class TestLineageService:
    """Tests for lineage service."""

    def setup_method(self):
        """Reset service before each test."""
        reset_lineage_store()
        reset_lineage_service()

    def test_create_record(self):
        """Test creating a record through the service."""
        service = get_lineage_service()
        record = service.create_record(
            record_type=RecordType.INTELLIGENCE,
            data={"indicator": "test.com"},
            created_by="test_user",
            tags=["test"],
        )

        assert record.record_id is not None
        assert record.created_by == "test_user"
        assert len(record.lineage_nodes) == 1
        assert record.lineage_nodes[0].is_root is True
        assert len(record.traceability_records) == 1

    def test_link_records(self):
        """Test linking two records."""
        service = get_lineage_service()

        parent = service.create_record(
            record_type=RecordType.INTELLIGENCE,
            data={"id": "parent"},
        )
        child = service.create_record(
            record_type=RecordType.FRAUD_SIGNAL,
            data={"id": "child"},
        )

        success = service.link_records(
            parent_id=parent.record_id,
            child_id=child.record_id,
            relationship_type="derived_from",
            impact_level=ImpactLevel.HIGH,
        )

        assert success is True
        assert parent.record_id in child.provenance_chain

    def test_get_provenance_chain(self):
        """Test getting provenance chain."""
        service = get_lineage_service()

        parent = service.create_record(record_type=RecordType.INTELLIGENCE, data={})
        child = service.create_record(record_type=RecordType.FRAUD_SIGNAL, data={})
        grandchild = service.create_record(record_type=RecordType.INVESTIGATION, data={})

        service.link_records(parent.record_id, child.record_id, "parent_of")
        service.link_records(child.record_id, grandchild.record_id, "parent_of")

        chain = service.get_provenance_chain(grandchild.record_id)
        assert chain is not None
        assert chain.total_records == 3
        assert chain.total_depth >= 1

    def test_build_dependency_graph(self):
        """Test building dependency graph."""
        service = get_lineage_service()

        root = service.create_record(record_type=RecordType.INTELLIGENCE, data={})
        dep1 = service.create_record(record_type=RecordType.FRAUD_SIGNAL, data={})
        dep2 = service.create_record(record_type=RecordType.INVESTIGATION, data={})

        service.link_records(root.record_id, dep1.record_id, "depends_on")
        service.link_records(root.record_id, dep2.record_id, "depends_on")

        graph = service.build_dependency_graph(root.record_id, direction="downstream")
        assert graph is not None
        assert graph.total_records >= 1
        assert graph.root_record_id == root.record_id

    def test_analyze_impact(self):
        """Test impact analysis."""
        service = get_lineage_service()

        root = service.create_record(record_type=RecordType.SECURITY_DECISION, data={"entity_id": "ent_001"})
        dep1 = service.create_record(record_type=RecordType.FRAUD_SIGNAL, data={"entity_id": "ent_002"})
        dep2 = service.create_record(record_type=RecordType.THREAT_INDICATOR, data={"entity_id": "ent_001"})

        service.link_records(root.record_id, dep1.record_id, "affects")
        service.link_records(root.record_id, dep2.record_id, "affects")

        impact = service.analyze_impact(root.record_id)
        assert impact is not None
        assert len(impact.impacted_records) >= 1
        assert len(impact.impacted_entities) >= 1
        assert impact.risk_score >= 0

    def test_verify_provenance(self):
        """Test provenance verification."""
        service = get_lineage_service()

        record = service.create_record(record_type=RecordType.INTELLIGENCE, data={})
        is_valid = service.verify_provenance(record.record_id)
        assert is_valid is True

    def test_search_records(self):
        """Test searching records."""
        service = get_lineage_service()

        service.create_record(RecordType.INTELLIGENCE, {"key": "val1"}, tags=["tag1"])
        service.create_record(RecordType.FRAUD_SIGNAL, {"key": "val2"}, tags=["tag2"])
        service.create_record(RecordType.THREAT_INDICATOR, {"key": "val3"}, tags=["tag1"])

        query = LineageQuery(tags=["tag1"])
        results = service.search_records(query)
        assert len(results) == 2

    def test_export_lineage_report(self):
        """Test exporting lineage report."""
        service = get_lineage_service()

        record = service.create_record(
            record_type=RecordType.INTELLIGENCE,
            data={"indicator": "test"},
        )

        report = service.export_lineage_report(
            record.record_id,
            include_graph=True,
            include_impact=True,
        )

        assert "record" in report
        assert "statistics" in report
        assert "generated_at" in report


class TestLineageThreadSafety:
    """Tests for thread safety."""

    def setup_method(self):
        """Reset store before each test."""
        reset_lineage_store()

    def test_concurrent_writes(self):
        """Test concurrent write operations."""
        store = get_lineage_store()
        errors = []

        def write_records(count):
            try:
                for i in range(count):
                    record = DataRecord(
                        record_type=RecordType.INTELLIGENCE,
                        data={"index": i, "thread": threading.current_thread().name},
                    )
                    store.store_record(record)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_records, args=(10,)) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        stats = store.get_stats()
        assert stats.total_records == 50

    def test_concurrent_reads(self):
        """Test concurrent read operations."""
        store = get_lineage_store()

        # Create some records
        record_ids = []
        for i in range(10):
            record = DataRecord(record_type=RecordType.INTELLIGENCE, data={"i": i})
            store.store_record(record)
            record_ids.append(record.record_id)

        results = []

        def read_records():
            for rid in record_ids:
                record = store.get_record(rid)
                results.append(record)

        threads = [threading.Thread(target=read_records) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 50

    def test_cache_concurrent_access(self):
        """Test cache thread safety."""
        store = get_lineage_store()
        record = DataRecord(record_type=RecordType.INTELLIGENCE, data={})
        store.store_record(record)

        def access_cache():
            for _ in range(100):
                store.get_record(record.record_id)

        threads = [threading.Thread(target=access_cache) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # If we get here without errors, the test passes


class TestLineageIntegration:
    """Integration tests for lineage system."""

    def setup_method(self):
        """Reset service before each test."""
        reset_lineage_store()
        reset_lineage_service()

    def test_full_lineage_workflow(self):
        """Test complete lineage tracking workflow."""
        service = get_lineage_service()

        # Create intelligence record
        intel = service.create_record(
            record_type=RecordType.INTELLIGENCE,
            data={
                "indicator": "malicious-domain.com",
                "type": "domain",
                "confidence": 0.95,
            },
            tags=["apt", "c2"],
        )

        # Create fraud signal derived from intelligence
        fraud = service.create_record(
            record_type=RecordType.FRAUD_SIGNAL,
            data={
                "account_id": "ACC-001",
                "signal_type": "suspicious_domain",
            },
        )
        service.link_records(intel.record_id, fraud.record_id, "derived_from", ImpactLevel.HIGH)

        # Create investigation from fraud signal
        investigation = service.create_record(
            record_type=RecordType.INVESTIGATION,
            data={
                "case_id": "INV-2024-001",
                "analyst": "soc_team",
            },
        )
        service.link_records(fraud.record_id, investigation.record_id, "triggers", ImpactLevel.CRITICAL)

        # Verify chain
        chain = service.get_provenance_chain(investigation.record_id)
        assert chain is not None
        assert chain.total_records == 3

        # Get impact analysis
        impact = service.analyze_impact(intel.record_id)
        assert impact is not None
        assert intel.record_id in impact.impacted_records

        # Verify provenance
        is_valid = service.verify_provenance(investigation.record_id)
        assert is_valid is True

        # Export report
        report = service.export_lineage_report(investigation.record_id)
        assert report["record"]["record_type"] == "investigation"
        assert report["statistics"]["total_records"] >= 3


class TestLineagePerformance:
    """Performance tests for lineage system."""

    def setup_method(self):
        """Reset store before each test."""
        reset_lineage_store()

    def test_o1_lookup_performance(self):
        """Test O(1) lookup performance."""
        store = get_lineage_store()

        # Create records
        record = DataRecord(record_type=RecordType.INTELLIGENCE, data={})
        store.store_record(record)

        # Measure lookup time
        start = time.time()
        for _ in range(10000):
            result = store.get_record(record.record_id)
            assert result is not None
        elapsed = time.time() - start

        assert elapsed < 1.0  # Should complete in under 1 second

    def test_bulk_insert_performance(self):
        """Test bulk insert performance."""
        store = get_lineage_store()

        start = time.time()
        for i in range(1000):
            record = DataRecord(
                record_type=RecordType.INTELLIGENCE,
                data={"index": i},
            )
            store.store_record(record)
        elapsed = time.time() - start

        assert elapsed < 5.0  # Should complete in under 5 seconds
        assert store.get_stats().total_records == 1000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
