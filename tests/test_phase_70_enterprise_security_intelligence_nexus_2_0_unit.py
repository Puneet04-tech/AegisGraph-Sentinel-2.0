import pytest
from src.phase_70_enterprise_security_intelligence_nexus_2_0.store import SecurityIntelligenceNexusStore
from src.phase_70_enterprise_security_intelligence_nexus_2_0.service import SecurityIntelligenceNexusService
from src.phase_70_enterprise_security_intelligence_nexus_2_0.analytics import SecurityIntelligenceNexusAnalytics


def test_record_creation():
    store = SecurityIntelligenceNexusStore()
    svc = SecurityIntelligenceNexusService(store)
    record = svc.create_globalintelligencehubstate(
        tenant_id="t1",
        record_id="rec-001", hub_id="nexus-hub-primary", connected_domains=["fraud", "cyber", "compliance", "AML"], ingestion_rate=4500.5, is_healthy=True
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"


def test_record_store_isolation():
    store = SecurityIntelligenceNexusStore()
    svc = SecurityIntelligenceNexusService(store)
    svc.create_globalintelligencehubstate("tenant_a", "rec-a1", hub_id="nexus-hub-primary", connected_domains=["fraud", "cyber", "compliance", "AML"], ingestion_rate=4500.5, is_healthy=True)
    svc.create_globalintelligencehubstate("tenant_b", "rec-b1", hub_id="nexus-hub-primary", connected_domains=["fraud", "cyber", "compliance", "AML"], ingestion_rate=4500.5, is_healthy=True)
    records_a = store.list_globalintelligencehubstates("tenant_a")
    records_b = store.list_globalintelligencehubstates("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"


def test_analytics_kpis():
    store = SecurityIntelligenceNexusStore()
    svc = SecurityIntelligenceNexusService(store)
    analytics = SecurityIntelligenceNexusAnalytics(store)
    svc.create_globalintelligencehubstate("t2", "rec-001", hub_id="nexus-hub-primary", connected_domains=["fraud", "cyber", "compliance", "AML"], ingestion_rate=4500.5, is_healthy=True)
    svc.create_unifiedanalyticsreport("t2", "rec-002", report_id="uar-2026-Q2", generated_by="Intelligence-Nexus-AI", domain_coverage={"fraud": 0.98, "cyber": 0.95, "compliance": 1.0}, threat_count=142)
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_items"] == 2
    assert "health_score" in kpis
