import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import ComplianceValidationPlatformCompliancePolicy, ComplianceValidationPlatformControlAssessment, ComplianceValidationPlatformComplianceAudit
from .store import ComplianceValidationPlatformStore


class ComplianceValidationPlatformService:
    def __init__(self, store: ComplianceValidationPlatformStore):
        self.store = store
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, tenant_id: str, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "timestamp": datetime.utcnow(),
            "tenant_id": tenant_id,
            "action": action,
            "details": details
        })

    def create_compliancepolicy(self, tenant_id: str, record_id: str, policy_id: str, regulation_name: str, rules_count: int, status: str) -> ComplianceValidationPlatformCompliancePolicy:
        item = ComplianceValidationPlatformCompliancePolicy(
            record_id=record_id, tenant_id=tenant_id, policy_id=policy_id, regulation_name=regulation_name, rules_count=rules_count, status=status,
            created_at=datetime.utcnow()
        )
        self.store.save_compliancepolicy(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'CompliancePolicy'.upper()}", {"record_id": record_id})
        return item

    def get_compliancepolicy(self, tenant_id: str, record_id: str) -> Optional[ComplianceValidationPlatformCompliancePolicy]:
        return self.store.get_compliancepolicy(tenant_id, record_id)

    def list_compliancepolicys(self, tenant_id: str) -> List[ComplianceValidationPlatformCompliancePolicy]:
        return self.store.list_compliancepolicys(tenant_id)

    def create_controlassessment(self, tenant_id: str, record_id: str, assessment_id: str, control_id: str, compliance_percentage: float, findings: List[str]) -> ComplianceValidationPlatformControlAssessment:
        item = ComplianceValidationPlatformControlAssessment(
            record_id=record_id, tenant_id=tenant_id, assessment_id=assessment_id, control_id=control_id, compliance_percentage=compliance_percentage, findings=findings,
            created_at=datetime.utcnow()
        )
        self.store.save_controlassessment(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'ControlAssessment'.upper()}", {"record_id": record_id})
        return item

    def get_controlassessment(self, tenant_id: str, record_id: str) -> Optional[ComplianceValidationPlatformControlAssessment]:
        return self.store.get_controlassessment(tenant_id, record_id)

    def list_controlassessments(self, tenant_id: str) -> List[ComplianceValidationPlatformControlAssessment]:
        return self.store.list_controlassessments(tenant_id)

    def create_complianceaudit(self, tenant_id: str, record_id: str, audit_id: str, auditor_name: str, violations_detected: int, audit_date: str) -> ComplianceValidationPlatformComplianceAudit:
        item = ComplianceValidationPlatformComplianceAudit(
            record_id=record_id, tenant_id=tenant_id, audit_id=audit_id, auditor_name=auditor_name, violations_detected=violations_detected, audit_date=audit_date,
            created_at=datetime.utcnow()
        )
        self.store.save_complianceaudit(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'ComplianceAudit'.upper()}", {"record_id": record_id})
        return item

    def get_complianceaudit(self, tenant_id: str, record_id: str) -> Optional[ComplianceValidationPlatformComplianceAudit]:
        return self.store.get_complianceaudit(tenant_id, record_id)

    def list_complianceaudits(self, tenant_id: str) -> List[ComplianceValidationPlatformComplianceAudit]:
        return self.store.list_complianceaudits(tenant_id)

def get_service() -> ComplianceValidationPlatformService:
    from .store import get_store
    return ComplianceValidationPlatformService(get_store())
