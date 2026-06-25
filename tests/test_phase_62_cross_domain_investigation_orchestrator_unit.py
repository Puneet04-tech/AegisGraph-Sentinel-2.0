import pytest
from src.phase_62_cross_domain_investigation_orchestrator.store import InvestigationOrchestratorStore
from src.phase_62_cross_domain_investigation_orchestrator.service import InvestigationOrchestratorService
from src.phase_62_cross_domain_investigation_orchestrator.analytics import InvestigationOrchestratorAnalytics


def test_record_creation():
    store = InvestigationOrchestratorStore()
    svc = InvestigationOrchestratorService(store)
    record = svc.create_investigationworkflow(
        tenant_id="t1",
        record_id="rec-001", workflow_id="wf-111", domain="cyber", current_state="IN_PROGRESS", assigned_analyst="analyst-x"
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"


def test_record_store_isolation():
    store = InvestigationOrchestratorStore()
    svc = InvestigationOrchestratorService(store)
    svc.create_investigationworkflow("tenant_a", "rec-a1", workflow_id="wf-111", domain="cyber", current_state="IN_PROGRESS", assigned_analyst="analyst-x")
    svc.create_investigationworkflow("tenant_b", "rec-b1", workflow_id="wf-111", domain="cyber", current_state="IN_PROGRESS", assigned_analyst="analyst-x")
    records_a = store.list_investigationworkflows("tenant_a")
    records_b = store.list_investigationworkflows("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"


def test_analytics_kpis():
    store = InvestigationOrchestratorStore()
    svc = InvestigationOrchestratorService(store)
    analytics = InvestigationOrchestratorAnalytics(store)
    svc.create_investigationworkflow("t2", "rec-001", workflow_id="wf-111", domain="cyber", current_state="IN_PROGRESS", assigned_analyst="analyst-x")
    svc.create_evidencecorrelation("t2", "rec-002", correlation_id="corr-456", evidence_ids=["ev-1", "ev-2"], score=0.88, description="Multi-domain correlation details")
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_items"] == 2
    assert "health_score" in kpis
