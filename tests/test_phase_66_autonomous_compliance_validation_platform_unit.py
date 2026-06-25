import pytest
from src.phase_66_autonomous_compliance_validation_platform.store import ComplianceValidationPlatformStore
from src.phase_66_autonomous_compliance_validation_platform.service import ComplianceValidationPlatformService
from src.phase_66_autonomous_compliance_validation_platform.analytics import ComplianceValidationPlatformAnalytics


def test_record_creation():
    store = ComplianceValidationPlatformStore()
    svc = ComplianceValidationPlatformService(store)
    record = svc.create_compliancepolicy(
        tenant_id="t1",
        record_id="rec-001", policy_id="pol-soc2", regulation_name="SOC_TYPE_II", rules_count=42, status="ENFORCED"
    )
    assert record.record_id == "rec-001"
    assert record.tenant_id == "t1"


def test_record_store_isolation():
    store = ComplianceValidationPlatformStore()
    svc = ComplianceValidationPlatformService(store)
    svc.create_compliancepolicy("tenant_a", "rec-a1", policy_id="pol-soc2", regulation_name="SOC_TYPE_II", rules_count=42, status="ENFORCED")
    svc.create_compliancepolicy("tenant_b", "rec-b1", policy_id="pol-soc2", regulation_name="SOC_TYPE_II", rules_count=42, status="ENFORCED")
    records_a = store.list_compliancepolicys("tenant_a")
    records_b = store.list_compliancepolicys("tenant_b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].record_id == "rec-a1"
    assert records_b[0].record_id == "rec-b1"


def test_analytics_kpis():
    store = ComplianceValidationPlatformStore()
    svc = ComplianceValidationPlatformService(store)
    analytics = ComplianceValidationPlatformAnalytics(store)
    svc.create_compliancepolicy("t2", "rec-001", policy_id="pol-soc2", regulation_name="SOC_TYPE_II", rules_count=42, status="ENFORCED")
    svc.create_controlassessment("t2", "rec-002", assessment_id="ass-889", control_id="CC6.1-Access-Control", compliance_percentage=98.5, findings=["All users have MFA enabled"])
    kpis = analytics.compute_kpis("t2")
    assert kpis["total_items"] == 2
    assert "health_score" in kpis
