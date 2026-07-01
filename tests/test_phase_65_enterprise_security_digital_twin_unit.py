import pytest
from src.phase_65_enterprise_security_digital_twin.store import SecurityDigitalTwinStore
from src.phase_65_enterprise_security_digital_twin.service import SecurityDigitalTwinService
from src.phase_65_enterprise_security_digital_twin.analytics import SecurityDigitalTwinAnalytics

def test_record_creation():
    store = SecurityDigitalTwinStore()
    svc = SecurityDigitalTwinService(store)
    record = svc.create_digitaltwinstate(
        tenant_id="t1",
        record_id="rec-001", state_id="twin-state-001", entity_id="active-directory-hub", posture_score=94.2, anomaly_detected=False
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"

def test_record_store_isolation():
    store = SecurityDigitalTwinStore()
    svc = SecurityDigitalTwinService(store)
    svc.create_digitaltwinstate("tenant_a", "rec-a1", state_id="twin-state-001", entity_id="active-directory-hub", posture_score=94.2, anomaly_detected=False)
    svc.create_digitaltwinstate("tenant_b", "rec-b1", state_id="twin-state-001", entity_id="active-directory-hub", posture_score=94.2, anomaly_detected=False)
    records_a = store.list_digitaltwinstates("tenant_a")
    records_b = store.list_digitaltwinstates("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"

def test_analytics_kpis():
    store = SecurityDigitalTwinStore()
    svc = SecurityDigitalTwinService(store)
    analytics = SecurityDigitalTwinAnalytics(store)
    svc.create_digitaltwinstate("t2", "rec-001", state_id="twin-state-001", entity_id="active-directory-hub", posture_score=94.2, anomaly_detected=False)
    svc.create_riskvisualizationnode("t2", "rec-002", node_id="vis-node-55", asset_name="firewall-primary", risk_level="LOW", x_y_coordinates=[12.5, 45.8])
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_items"] == 2
    assert "health_score" in kpis
