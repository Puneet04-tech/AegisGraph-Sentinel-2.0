import pytest
from datetime import datetime
from src.phase_155_security_observability_intelligence_platform.models import SecurityObservabilityIntelligencePlatformRecord, SecurityObservabilityIntelligencePlatformEvent, SecurityObservabilityIntelligencePlatformAlert
from src.phase_155_security_observability_intelligence_platform.store import SecurityObservabilityIntelligencePlatformStore
from src.phase_155_security_observability_intelligence_platform.service import SecurityObservabilityIntelligencePlatformService
from src.phase_155_security_observability_intelligence_platform.analytics import SecurityObservabilityIntelligencePlatformAnalytics


def test_record_creation():
    store = SecurityObservabilityIntelligencePlatformStore()
    svc = SecurityObservabilityIntelligencePlatformService(store)
    record = svc.create_record(
        tenant_id="t1",
        record_id="rec-001",
        name="Test Record",
        status="ACTIVE"
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"
    assert record.status == "ACTIVE"


def test_record_store_isolation():
    store = SecurityObservabilityIntelligencePlatformStore()
    svc = SecurityObservabilityIntelligencePlatformService(store)
    svc.create_record("tenant_a", "rec-a1", "Record A1", "ACTIVE")
    svc.create_record("tenant_b", "rec-b1", "Record B1", "ACTIVE")
    records_a = store.list_records("tenant_a")
    records_b = store.list_records("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"


def test_analytics_kpis():
    store = SecurityObservabilityIntelligencePlatformStore()
    svc = SecurityObservabilityIntelligencePlatformService(store)
    analytics = SecurityObservabilityIntelligencePlatformAnalytics(store)
    svc.create_record("t2", "rec-001", "R1", "ACTIVE")
    svc.create_record("t2", "rec-002", "R2", "INACTIVE")
    svc.create_alert("t2", "alt-001", "Test Alert", "HIGH")
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_records"] == 2
    assert kpis["total_alerts"] == 1
    assert "health_score" in kpis
