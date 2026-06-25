import pytest
from src.phase_64_autonomous_threat_simulation_platform.store import ThreatSimulationPlatformStore
from src.phase_64_autonomous_threat_simulation_platform.service import ThreatSimulationPlatformService
from src.phase_64_autonomous_threat_simulation_platform.analytics import ThreatSimulationPlatformAnalytics


def test_record_creation():
    store = ThreatSimulationPlatformStore()
    svc = ThreatSimulationPlatformService(store)
    record = svc.create_threatscenario(
        tenant_id="t1",
        record_id="rec-001", scenario_id="scen-888", scenario_type="RANSOMWARE", steps=["phishing", "lateral_movement", "exfiltration"], target_assets=["database-1", "user-laptops"]
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"


def test_record_store_isolation():
    store = ThreatSimulationPlatformStore()
    svc = ThreatSimulationPlatformService(store)
    svc.create_threatscenario("tenant_a", "rec-a1", scenario_id="scen-888", scenario_type="RANSOMWARE", steps=["phishing", "lateral_movement", "exfiltration"], target_assets=["database-1", "user-laptops"])
    svc.create_threatscenario("tenant_b", "rec-b1", scenario_id="scen-888", scenario_type="RANSOMWARE", steps=["phishing", "lateral_movement", "exfiltration"], target_assets=["database-1", "user-laptops"])
    records_a = store.list_threatscenarios("tenant_a")
    records_b = store.list_threatscenarios("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"


def test_analytics_kpis():
    store = ThreatSimulationPlatformStore()
    svc = ThreatSimulationPlatformService(store)
    analytics = ThreatSimulationPlatformAnalytics(store)
    svc.create_threatscenario("t2", "rec-001", scenario_id="scen-888", scenario_type="RANSOMWARE", steps=["phishing", "lateral_movement", "exfiltration"], target_assets=["database-1", "user-laptops"])
    svc.create_fraudsimulation("t2", "rec-002", simulation_id="sim-002", campaign_type="IDENTITY_THEFT", detection_rate=0.76, status="COMPLETED")
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_items"] == 2
    assert "health_score" in kpis
