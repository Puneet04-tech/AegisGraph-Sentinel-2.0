import pytest
from src.phase_61_autonomous_security_knowledge_graph_engine.store import SecurityKnowledgeGraphStore
from src.phase_61_autonomous_security_knowledge_graph_engine.service import SecurityKnowledgeGraphService
from src.phase_61_autonomous_security_knowledge_graph_engine.analytics import SecurityKnowledgeGraphAnalytics


def test_record_creation():
    store = SecurityKnowledgeGraphStore()
    svc = SecurityKnowledgeGraphService(store)
    record = svc.create_entityrelation(
        tenant_id="t1",
        record_id="rec-001", relation_id="rel-123", source_entity="entity-A", target_entity="entity-B", relation_type="FRIEND", confidence=0.95
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"


def test_record_store_isolation():
    store = SecurityKnowledgeGraphStore()
    svc = SecurityKnowledgeGraphService(store)
    svc.create_entityrelation("tenant_a", "rec-a1", relation_id="rel-123", source_entity="entity-A", target_entity="entity-B", relation_type="FRIEND", confidence=0.95)
    svc.create_entityrelation("tenant_b", "rec-b1", relation_id="rel-123", source_entity="entity-A", target_entity="entity-B", relation_type="FRIEND", confidence=0.95)
    records_a = store.list_entityrelations("tenant_a")
    records_b = store.list_entityrelations("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"


def test_analytics_kpis():
    store = SecurityKnowledgeGraphStore()
    svc = SecurityKnowledgeGraphService(store)
    analytics = SecurityKnowledgeGraphAnalytics(store)
    svc.create_entityrelation("t2", "rec-001", relation_id="rel-123", source_entity="entity-A", target_entity="entity-B", relation_type="FRIEND", confidence=0.95)
    svc.create_riskpropagationpath("t2", "rec-002", path_id="path-001", nodes=["node-1", "node-2"], total_risk=85.5, mitigation_status="MITIGATED")
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_items"] == 2
    assert "health_score" in kpis
