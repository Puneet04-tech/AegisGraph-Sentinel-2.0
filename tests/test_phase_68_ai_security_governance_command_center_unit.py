import pytest
from src.phase_68_ai_security_governance_command_center.store import SecurityGovernanceCommandCenterStore
from src.phase_68_ai_security_governance_command_center.service import SecurityGovernanceCommandCenterService
from src.phase_68_ai_security_governance_command_center.analytics import SecurityGovernanceCommandCenterAnalytics


def test_record_creation():
    store = SecurityGovernanceCommandCenterStore()
    svc = SecurityGovernanceCommandCenterService(store)
    record = svc.create_modelgovernancerecord(
        tenant_id="t1",
        record_id="rec-001", model_id="model-sentinel-GNN", model_version="v2.4.1", bias_score=0.02, is_approved=True
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"


def test_record_store_isolation():
    store = SecurityGovernanceCommandCenterStore()
    svc = SecurityGovernanceCommandCenterService(store)
    svc.create_modelgovernancerecord("tenant_a", "rec-a1", model_id="model-sentinel-GNN", model_version="v2.4.1", bias_score=0.02, is_approved=True)
    svc.create_modelgovernancerecord("tenant_b", "rec-b1", model_id="model-sentinel-GNN", model_version="v2.4.1", bias_score=0.02, is_approved=True)
    records_a = store.list_modelgovernancerecords("tenant_a")
    records_b = store.list_modelgovernancerecords("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"


def test_analytics_kpis():
    store = SecurityGovernanceCommandCenterStore()
    svc = SecurityGovernanceCommandCenterService(store)
    analytics = SecurityGovernanceCommandCenterAnalytics(store)
    svc.create_modelgovernancerecord("t2", "rec-001", model_id="model-sentinel-GNN", model_version="v2.4.1", bias_score=0.02, is_approved=True)
    svc.create_promptauditrecord("t2", "rec-002", audit_id="pa-9911", prompt_hash="a8f3b2cd", risk_level="LOW", policy_violations=[])
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_items"] == 2
    assert "health_score" in kpis
