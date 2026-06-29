import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import SecurityGovernanceCommandCenterModelGovernanceRecord, SecurityGovernanceCommandCenterPromptAuditRecord, SecurityGovernanceCommandCenterRiskMonitorState
from .store import SecurityGovernanceCommandCenterStore


class SecurityGovernanceCommandCenterService:
    def __init__(self, store: SecurityGovernanceCommandCenterStore):
        self.store = store
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, tenant_id: str, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "timestamp": datetime.utcnow(),
            "tenant_id": tenant_id,
            "action": action,
            "details": details
        })

    def create_modelgovernancerecord(self, tenant_id: str, record_id: str, model_id: str, model_version: str, bias_score: float, is_approved: bool) -> SecurityGovernanceCommandCenterModelGovernanceRecord:
        item = SecurityGovernanceCommandCenterModelGovernanceRecord(
            record_id=record_id, tenant_id=tenant_id, model_id=model_id, model_version=model_version, bias_score=bias_score, is_approved=is_approved,
            created_at=datetime.utcnow()
        )
        self.store.save_modelgovernancerecord(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'ModelGovernanceRecord'.upper()}", {"record_id": record_id})
        return item

    def get_modelgovernancerecord(self, tenant_id: str, record_id: str) -> Optional[SecurityGovernanceCommandCenterModelGovernanceRecord]:
        return self.store.get_modelgovernancerecord(tenant_id, record_id)

    def list_modelgovernancerecords(self, tenant_id: str) -> List[SecurityGovernanceCommandCenterModelGovernanceRecord]:
        return self.store.list_modelgovernancerecords(tenant_id)

    def create_promptauditrecord(self, tenant_id: str, record_id: str, audit_id: str, prompt_hash: str, risk_level: str, policy_violations: List[str]) -> SecurityGovernanceCommandCenterPromptAuditRecord:
        item = SecurityGovernanceCommandCenterPromptAuditRecord(
            record_id=record_id, tenant_id=tenant_id, audit_id=audit_id, prompt_hash=prompt_hash, risk_level=risk_level, policy_violations=policy_violations,
            created_at=datetime.utcnow()
        )
        self.store.save_promptauditrecord(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'PromptAuditRecord'.upper()}", {"record_id": record_id})
        return item

    def get_promptauditrecord(self, tenant_id: str, record_id: str) -> Optional[SecurityGovernanceCommandCenterPromptAuditRecord]:
        return self.store.get_promptauditrecord(tenant_id, record_id)

    def list_promptauditrecords(self, tenant_id: str) -> List[SecurityGovernanceCommandCenterPromptAuditRecord]:
        return self.store.list_promptauditrecords(tenant_id)

    def create_riskmonitorstate(self, tenant_id: str, record_id: str, state_id: str, total_governed_models: int, anomalies_count: int, last_checked: str) -> SecurityGovernanceCommandCenterRiskMonitorState:
        item = SecurityGovernanceCommandCenterRiskMonitorState(
            record_id=record_id, tenant_id=tenant_id, state_id=state_id, total_governed_models=total_governed_models, anomalies_count=anomalies_count, last_checked=last_checked,
            created_at=datetime.utcnow()
        )
        self.store.save_riskmonitorstate(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'RiskMonitorState'.upper()}", {"record_id": record_id})
        return item

    def get_riskmonitorstate(self, tenant_id: str, record_id: str) -> Optional[SecurityGovernanceCommandCenterRiskMonitorState]:
        return self.store.get_riskmonitorstate(tenant_id, record_id)

    def list_riskmonitorstates(self, tenant_id: str) -> List[SecurityGovernanceCommandCenterRiskMonitorState]:
        return self.store.list_riskmonitorstates(tenant_id)

def get_service() -> SecurityGovernanceCommandCenterService:
    from .store import get_store
    return SecurityGovernanceCommandCenterService(get_store())
