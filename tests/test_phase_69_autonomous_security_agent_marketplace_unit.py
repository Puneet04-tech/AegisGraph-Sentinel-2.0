import pytest
from src.phase_69_autonomous_security_agent_marketplace.store import SecurityAgentMarketplaceStore
from src.phase_69_autonomous_security_agent_marketplace.service import SecurityAgentMarketplaceService
from src.phase_69_autonomous_security_agent_marketplace.analytics import SecurityAgentMarketplaceAnalytics


def test_record_creation():
    store = SecurityAgentMarketplaceStore()
    svc = SecurityAgentMarketplaceService(store)
    record = svc.create_agentregistration(
        tenant_id="t1",
        record_id="rec-001", agent_id="agent-biometrics-analyst", agent_name="Voice-Behavioral-Agent", capabilities=["voice_stress", "keystroke_biometrics"], status="ACTIVE"
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"


def test_record_store_isolation():
    store = SecurityAgentMarketplaceStore()
    svc = SecurityAgentMarketplaceService(store)
    svc.create_agentregistration("tenant_a", "rec-a1", agent_id="agent-biometrics-analyst", agent_name="Voice-Behavioral-Agent", capabilities=["voice_stress", "keystroke_biometrics"], status="ACTIVE")
    svc.create_agentregistration("tenant_b", "rec-b1", agent_id="agent-biometrics-analyst", agent_name="Voice-Behavioral-Agent", capabilities=["voice_stress", "keystroke_biometrics"], status="ACTIVE")
    records_a = store.list_agentregistrations("tenant_a")
    records_b = store.list_agentregistrations("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"


def test_analytics_kpis():
    store = SecurityAgentMarketplaceStore()
    svc = SecurityAgentMarketplaceService(store)
    analytics = SecurityAgentMarketplaceAnalytics(store)
    svc.create_agentregistration("t2", "rec-001", agent_id="agent-biometrics-analyst", agent_name="Voice-Behavioral-Agent", capabilities=["voice_stress", "keystroke_biometrics"], status="ACTIVE")
    svc.create_orchestrationsession("t2", "rec-002", session_id="orch-session-555", active_agents=["voice-agent", "graph-agent"], task_status="COLLABORATING", messages_exchanged=34)
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_items"] == 2
    assert "health_score" in kpis
