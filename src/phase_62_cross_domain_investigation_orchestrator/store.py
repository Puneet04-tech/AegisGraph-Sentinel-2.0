import threading
from typing import Dict, List, Optional
from .models import InvestigationOrchestratorInvestigationWorkflow, InvestigationOrchestratorEvidenceCorrelation, InvestigationOrchestratorEscalationRecord


class InvestigationOrchestratorStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._investigationworkflows: Dict[str, Dict[str, InvestigationOrchestratorInvestigationWorkflow]] = {}
        self._evidencecorrelations: Dict[str, Dict[str, InvestigationOrchestratorEvidenceCorrelation]] = {}
        self._escalationrecords: Dict[str, Dict[str, InvestigationOrchestratorEscalationRecord]] = {}

    def save_investigationworkflow(self, tenant_id: str, item: InvestigationOrchestratorInvestigationWorkflow) -> None:
        with self._lock:
            if tenant_id not in self._investigationworkflows:
                self._investigationworkflows[tenant_id] = {}
            self._investigationworkflows[tenant_id][item.record_id] = item

    def get_investigationworkflow(self, tenant_id: str, record_id: str) -> Optional[InvestigationOrchestratorInvestigationWorkflow]:
        with self._lock:
            return self._investigationworkflows.get(tenant_id, {}).get(record_id)

    def list_investigationworkflows(self, tenant_id: str) -> List[InvestigationOrchestratorInvestigationWorkflow]:
        with self._lock:
            return list(self._investigationworkflows.get(tenant_id, {}).values())

    def save_evidencecorrelation(self, tenant_id: str, item: InvestigationOrchestratorEvidenceCorrelation) -> None:
        with self._lock:
            if tenant_id not in self._evidencecorrelations:
                self._evidencecorrelations[tenant_id] = {}
            self._evidencecorrelations[tenant_id][item.record_id] = item

    def get_evidencecorrelation(self, tenant_id: str, record_id: str) -> Optional[InvestigationOrchestratorEvidenceCorrelation]:
        with self._lock:
            return self._evidencecorrelations.get(tenant_id, {}).get(record_id)

    def list_evidencecorrelations(self, tenant_id: str) -> List[InvestigationOrchestratorEvidenceCorrelation]:
        with self._lock:
            return list(self._evidencecorrelations.get(tenant_id, {}).values())

    def save_escalationrecord(self, tenant_id: str, item: InvestigationOrchestratorEscalationRecord) -> None:
        with self._lock:
            if tenant_id not in self._escalationrecords:
                self._escalationrecords[tenant_id] = {}
            self._escalationrecords[tenant_id][item.record_id] = item

    def get_escalationrecord(self, tenant_id: str, record_id: str) -> Optional[InvestigationOrchestratorEscalationRecord]:
        with self._lock:
            return self._escalationrecords.get(tenant_id, {}).get(record_id)

    def list_escalationrecords(self, tenant_id: str) -> List[InvestigationOrchestratorEscalationRecord]:
        with self._lock:
            return list(self._escalationrecords.get(tenant_id, {}).values())

_store_instance = InvestigationOrchestratorStore()

def get_store() -> InvestigationOrchestratorStore:
    return _store_instance
