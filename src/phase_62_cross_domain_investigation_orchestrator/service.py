import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import InvestigationOrchestratorInvestigationWorkflow, InvestigationOrchestratorEvidenceCorrelation, InvestigationOrchestratorEscalationRecord
from .store import InvestigationOrchestratorStore


class InvestigationOrchestratorService:
    def __init__(self, store: InvestigationOrchestratorStore):
        self.store = store
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, tenant_id: str, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "timestamp": datetime.utcnow(),
            "tenant_id": tenant_id,
            "action": action,
            "details": details
        })

    def create_investigationworkflow(self, tenant_id: str, record_id: str, workflow_id: str, domain: str, current_state: str, assigned_analyst: str) -> InvestigationOrchestratorInvestigationWorkflow:
        item = InvestigationOrchestratorInvestigationWorkflow(
            record_id=record_id, tenant_id=tenant_id, workflow_id=workflow_id, domain=domain, current_state=current_state, assigned_analyst=assigned_analyst,
            created_at=datetime.utcnow()
        )
        self.store.save_investigationworkflow(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'InvestigationWorkflow'.upper()}", {"record_id": record_id})
        return item

    def get_investigationworkflow(self, tenant_id: str, record_id: str) -> Optional[InvestigationOrchestratorInvestigationWorkflow]:
        return self.store.get_investigationworkflow(tenant_id, record_id)

    def list_investigationworkflows(self, tenant_id: str) -> List[InvestigationOrchestratorInvestigationWorkflow]:
        return self.store.list_investigationworkflows(tenant_id)

    def create_evidencecorrelation(self, tenant_id: str, record_id: str, correlation_id: str, evidence_ids: List[str], score: float, description: str) -> InvestigationOrchestratorEvidenceCorrelation:
        item = InvestigationOrchestratorEvidenceCorrelation(
            record_id=record_id, tenant_id=tenant_id, correlation_id=correlation_id, evidence_ids=evidence_ids, score=score, description=description,
            created_at=datetime.utcnow()
        )
        self.store.save_evidencecorrelation(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'EvidenceCorrelation'.upper()}", {"record_id": record_id})
        return item

    def get_evidencecorrelation(self, tenant_id: str, record_id: str) -> Optional[InvestigationOrchestratorEvidenceCorrelation]:
        return self.store.get_evidencecorrelation(tenant_id, record_id)

    def list_evidencecorrelations(self, tenant_id: str) -> List[InvestigationOrchestratorEvidenceCorrelation]:
        return self.store.list_evidencecorrelations(tenant_id)

    def create_escalationrecord(self, tenant_id: str, record_id: str, escalation_id: str, reason: str, priority: str, resolved: bool) -> InvestigationOrchestratorEscalationRecord:
        item = InvestigationOrchestratorEscalationRecord(
            record_id=record_id, tenant_id=tenant_id, escalation_id=escalation_id, reason=reason, priority=priority, resolved=resolved,
            created_at=datetime.utcnow()
        )
        self.store.save_escalationrecord(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'EscalationRecord'.upper()}", {"record_id": record_id})
        return item

    def get_escalationrecord(self, tenant_id: str, record_id: str) -> Optional[InvestigationOrchestratorEscalationRecord]:
        return self.store.get_escalationrecord(tenant_id, record_id)

    def list_escalationrecords(self, tenant_id: str) -> List[InvestigationOrchestratorEscalationRecord]:
        return self.store.list_escalationrecords(tenant_id)

def get_service() -> InvestigationOrchestratorService:
    from .store import get_store
    return InvestigationOrchestratorService(get_store())
