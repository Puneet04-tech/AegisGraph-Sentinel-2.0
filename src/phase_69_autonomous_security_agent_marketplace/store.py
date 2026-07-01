import threading
from typing import Dict, List, Optional
from .models import SecurityAgentMarketplaceAgentRegistration, SecurityAgentMarketplaceOrchestrationSession, SecurityAgentMarketplaceAgentCapability


class SecurityAgentMarketplaceStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._agentregistrations: Dict[str, Dict[str, SecurityAgentMarketplaceAgentRegistration]] = {}
        self._orchestrationsessions: Dict[str, Dict[str, SecurityAgentMarketplaceOrchestrationSession]] = {}
        self._agentcapabilitys: Dict[str, Dict[str, SecurityAgentMarketplaceAgentCapability]] = {}

    def save_agentregistration(self, tenant_id: str, item: SecurityAgentMarketplaceAgentRegistration) -> None:
        with self._lock:
            if tenant_id not in self._agentregistrations:
                self._agentregistrations[tenant_id] = {}
            self._agentregistrations[tenant_id][item.record_id] = item

    def get_agentregistration(self, tenant_id: str, record_id: str) -> Optional[SecurityAgentMarketplaceAgentRegistration]:
        with self._lock:
            return self._agentregistrations.get(tenant_id, {}).get(record_id)

    def list_agentregistrations(self, tenant_id: str) -> List[SecurityAgentMarketplaceAgentRegistration]:
        with self._lock:
            return list(self._agentregistrations.get(tenant_id, {}).values())

    def save_orchestrationsession(self, tenant_id: str, item: SecurityAgentMarketplaceOrchestrationSession) -> None:
        with self._lock:
            if tenant_id not in self._orchestrationsessions:
                self._orchestrationsessions[tenant_id] = {}
            self._orchestrationsessions[tenant_id][item.record_id] = item

    def get_orchestrationsession(self, tenant_id: str, record_id: str) -> Optional[SecurityAgentMarketplaceOrchestrationSession]:
        with self._lock:
            return self._orchestrationsessions.get(tenant_id, {}).get(record_id)

    def list_orchestrationsessions(self, tenant_id: str) -> List[SecurityAgentMarketplaceOrchestrationSession]:
        with self._lock:
            return list(self._orchestrationsessions.get(tenant_id, {}).values())

    def save_agentcapability(self, tenant_id: str, item: SecurityAgentMarketplaceAgentCapability) -> None:
        with self._lock:
            if tenant_id not in self._agentcapabilitys:
                self._agentcapabilitys[tenant_id] = {}
            self._agentcapabilitys[tenant_id][item.record_id] = item

    def get_agentcapability(self, tenant_id: str, record_id: str) -> Optional[SecurityAgentMarketplaceAgentCapability]:
        with self._lock:
            return self._agentcapabilitys.get(tenant_id, {}).get(record_id)

    def list_agentcapabilitys(self, tenant_id: str) -> List[SecurityAgentMarketplaceAgentCapability]:
        with self._lock:
            return list(self._agentcapabilitys.get(tenant_id, {}).values())

_store_instance = SecurityAgentMarketplaceStore()

def get_store() -> SecurityAgentMarketplaceStore:
    return _store_instance
