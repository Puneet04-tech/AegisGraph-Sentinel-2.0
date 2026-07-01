import threading
from typing import Dict, List, Optional
from .models import SecurityGovernanceCommandCenterModelGovernanceRecord, SecurityGovernanceCommandCenterPromptAuditRecord, SecurityGovernanceCommandCenterRiskMonitorState


class SecurityGovernanceCommandCenterStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._modelgovernancerecords: Dict[str, Dict[str, SecurityGovernanceCommandCenterModelGovernanceRecord]] = {}
        self._promptauditrecords: Dict[str, Dict[str, SecurityGovernanceCommandCenterPromptAuditRecord]] = {}
        self._riskmonitorstates: Dict[str, Dict[str, SecurityGovernanceCommandCenterRiskMonitorState]] = {}

    def save_modelgovernancerecord(self, tenant_id: str, item: SecurityGovernanceCommandCenterModelGovernanceRecord) -> None:
        with self._lock:
            if tenant_id not in self._modelgovernancerecords:
                self._modelgovernancerecords[tenant_id] = {}
            self._modelgovernancerecords[tenant_id][item.record_id] = item

    def get_modelgovernancerecord(self, tenant_id: str, record_id: str) -> Optional[SecurityGovernanceCommandCenterModelGovernanceRecord]:
        with self._lock:
            return self._modelgovernancerecords.get(tenant_id, {}).get(record_id)

    def list_modelgovernancerecords(self, tenant_id: str) -> List[SecurityGovernanceCommandCenterModelGovernanceRecord]:
        with self._lock:
            return list(self._modelgovernancerecords.get(tenant_id, {}).values())

    def save_promptauditrecord(self, tenant_id: str, item: SecurityGovernanceCommandCenterPromptAuditRecord) -> None:
        with self._lock:
            if tenant_id not in self._promptauditrecords:
                self._promptauditrecords[tenant_id] = {}
            self._promptauditrecords[tenant_id][item.record_id] = item

    def get_promptauditrecord(self, tenant_id: str, record_id: str) -> Optional[SecurityGovernanceCommandCenterPromptAuditRecord]:
        with self._lock:
            return self._promptauditrecords.get(tenant_id, {}).get(record_id)

    def list_promptauditrecords(self, tenant_id: str) -> List[SecurityGovernanceCommandCenterPromptAuditRecord]:
        with self._lock:
            return list(self._promptauditrecords.get(tenant_id, {}).values())

    def save_riskmonitorstate(self, tenant_id: str, item: SecurityGovernanceCommandCenterRiskMonitorState) -> None:
        with self._lock:
            if tenant_id not in self._riskmonitorstates:
                self._riskmonitorstates[tenant_id] = {}
            self._riskmonitorstates[tenant_id][item.record_id] = item

    def get_riskmonitorstate(self, tenant_id: str, record_id: str) -> Optional[SecurityGovernanceCommandCenterRiskMonitorState]:
        with self._lock:
            return self._riskmonitorstates.get(tenant_id, {}).get(record_id)

    def list_riskmonitorstates(self, tenant_id: str) -> List[SecurityGovernanceCommandCenterRiskMonitorState]:
        with self._lock:
            return list(self._riskmonitorstates.get(tenant_id, {}).values())

_store_instance = SecurityGovernanceCommandCenterStore()

def get_store() -> SecurityGovernanceCommandCenterStore:
    return _store_instance
