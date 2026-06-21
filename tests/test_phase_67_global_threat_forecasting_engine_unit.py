import pytest
from src.phase_67_global_threat_forecasting_engine.store import ThreatForecastingEngineStore
from src.phase_67_global_threat_forecasting_engine.service import ThreatForecastingEngineService
from src.phase_67_global_threat_forecasting_engine.analytics import ThreatForecastingEngineAnalytics


def test_record_creation():
    store = ThreatForecastingEngineStore()
    svc = ThreatForecastingEngineService(store)
    record = svc.create_threatforecast(
        tenant_id="t1",
        record_id="rec-001", forecast_id="fore-991", predicted_threat_type="APISpamming", likelihood=0.82, target_sectors=["finance", "e-commerce"]
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"


def test_record_store_isolation():
    store = ThreatForecastingEngineStore()
    svc = ThreatForecastingEngineService(store)
    svc.create_threatforecast("tenant_a", "rec-a1", forecast_id="fore-991", predicted_threat_type="APISpamming", likelihood=0.82, target_sectors=["finance", "e-commerce"])
    svc.create_threatforecast("tenant_b", "rec-b1", forecast_id="fore-991", predicted_threat_type="APISpamming", likelihood=0.82, target_sectors=["finance", "e-commerce"])
    records_a = store.list_threatforecasts("tenant_a")
    records_b = store.list_threatforecasts("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"


def test_analytics_kpis():
    store = ThreatForecastingEngineStore()
    svc = ThreatForecastingEngineService(store)
    analytics = ThreatForecastingEngineAnalytics(store)
    svc.create_threatforecast("t2", "rec-001", forecast_id="fore-991", predicted_threat_type="APISpamming", likelihood=0.82, target_sectors=["finance", "e-commerce"])
    svc.create_trendindicator("t2", "rec-002", indicator_id="ind-43", metric_name="credential_stuffing_volume", trend_direction="INCREASING", change_percentage=15.4)
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_items"] == 2
    assert "health_score" in kpis
