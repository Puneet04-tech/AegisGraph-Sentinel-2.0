import pytest
from src.phase_63_enterprise_security_decision_intelligence_platform.store import DecisionIntelligencePlatformStore
from src.phase_63_enterprise_security_decision_intelligence_platform.service import DecisionIntelligencePlatformService
from src.phase_63_enterprise_security_decision_intelligence_platform.analytics import DecisionIntelligencePlatformAnalytics


def test_record_creation():
    store = DecisionIntelligencePlatformStore()
    svc = DecisionIntelligencePlatformService(store)
    record = svc.create_decisioncontext(
        tenant_id="t1",
        record_id="rec-001", decision_id="dec-777", action_taken="BLOCK_IP", rationales=["High anomalous traffic", "Known bad IP"], confidence=0.99
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"


def test_record_store_isolation():
    store = DecisionIntelligencePlatformStore()
    svc = DecisionIntelligencePlatformService(store)
    svc.create_decisioncontext("tenant_a", "rec-a1", decision_id="dec-777", action_taken="BLOCK_IP", rationales=["High anomalous traffic", "Known bad IP"], confidence=0.99)
    svc.create_decisioncontext("tenant_b", "rec-b1", decision_id="dec-777", action_taken="BLOCK_IP", rationales=["High anomalous traffic", "Known bad IP"], confidence=0.99)
    records_a = store.list_decisioncontexts("tenant_a")
    records_b = store.list_decisioncontexts("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"


def test_analytics_kpis():
    store = DecisionIntelligencePlatformStore()
    svc = DecisionIntelligencePlatformService(store)
    analytics = DecisionIntelligencePlatformAnalytics(store)
    svc.create_decisioncontext("t2", "rec-001", decision_id="dec-777", action_taken="BLOCK_IP", rationales=["High anomalous traffic", "Known bad IP"], confidence=0.99)
    svc.create_explainabilityreport("t2", "rec-002", report_id="rep-321", model_name="XGBoost-Threat", feature_importances={"geo_mismatch": 0.65, "ip_reputation": 0.35}, explanation_text="Model output driven by geographic mismatch and IP reputation score.")
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_items"] == 2
    assert "health_score" in kpis
