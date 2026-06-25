import threading
from typing import Dict, List, Optional
from .models import ComplianceValidationPlatformCompliancePolicy, ComplianceValidationPlatformControlAssessment, ComplianceValidationPlatformComplianceAudit


class ComplianceValidationPlatformStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._compliancepolicys: Dict[str, Dict[str, ComplianceValidationPlatformCompliancePolicy]] = {}
        self._controlassessments: Dict[str, Dict[str, ComplianceValidationPlatformControlAssessment]] = {}
        self._complianceaudits: Dict[str, Dict[str, ComplianceValidationPlatformComplianceAudit]] = {}

    def save_compliancepolicy(self, tenant_id: str, item: ComplianceValidationPlatformCompliancePolicy) -> None:
        with self._lock:
            if tenant_id not in self._compliancepolicys:
                self._compliancepolicys[tenant_id] = {}
            self._compliancepolicys[tenant_id][item.record_id] = item

    def get_compliancepolicy(self, tenant_id: str, record_id: str) -> Optional[ComplianceValidationPlatformCompliancePolicy]:
        with self._lock:
            return self._compliancepolicys.get(tenant_id, {}).get(record_id)

    def list_compliancepolicys(self, tenant_id: str) -> List[ComplianceValidationPlatformCompliancePolicy]:
        with self._lock:
            return list(self._compliancepolicys.get(tenant_id, {}).values())

    def save_controlassessment(self, tenant_id: str, item: ComplianceValidationPlatformControlAssessment) -> None:
        with self._lock:
            if tenant_id not in self._controlassessments:
                self._controlassessments[tenant_id] = {}
            self._controlassessments[tenant_id][item.record_id] = item

    def get_controlassessment(self, tenant_id: str, record_id: str) -> Optional[ComplianceValidationPlatformControlAssessment]:
        with self._lock:
            return self._controlassessments.get(tenant_id, {}).get(record_id)

    def list_controlassessments(self, tenant_id: str) -> List[ComplianceValidationPlatformControlAssessment]:
        with self._lock:
            return list(self._controlassessments.get(tenant_id, {}).values())

    def save_complianceaudit(self, tenant_id: str, item: ComplianceValidationPlatformComplianceAudit) -> None:
        with self._lock:
            if tenant_id not in self._complianceaudits:
                self._complianceaudits[tenant_id] = {}
            self._complianceaudits[tenant_id][item.record_id] = item

    def get_complianceaudit(self, tenant_id: str, record_id: str) -> Optional[ComplianceValidationPlatformComplianceAudit]:
        with self._lock:
            return self._complianceaudits.get(tenant_id, {}).get(record_id)

    def list_complianceaudits(self, tenant_id: str) -> List[ComplianceValidationPlatformComplianceAudit]:
        with self._lock:
            return list(self._complianceaudits.get(tenant_id, {}).values())

_store_instance = ComplianceValidationPlatformStore()

def get_store() -> ComplianceValidationPlatformStore:
    return _store_instance
