import threading
from typing import Dict, List, Optional
from .models import SecurityKnowledgeGraphEntityRelation, SecurityKnowledgeGraphRiskPropagationPath, SecurityKnowledgeGraphFederatedKnowledgeNode


class SecurityKnowledgeGraphStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._entityrelations: Dict[str, Dict[str, SecurityKnowledgeGraphEntityRelation]] = {}
        self._riskpropagationpaths: Dict[str, Dict[str, SecurityKnowledgeGraphRiskPropagationPath]] = {}
        self._federatedknowledgenodes: Dict[str, Dict[str, SecurityKnowledgeGraphFederatedKnowledgeNode]] = {}

    def save_entityrelation(self, tenant_id: str, item: SecurityKnowledgeGraphEntityRelation) -> None:
        with self._lock:
            if tenant_id not in self._entityrelations:
                self._entityrelations[tenant_id] = {}
            self._entityrelations[tenant_id][item.record_id] = item

    def get_entityrelation(self, tenant_id: str, record_id: str) -> Optional[SecurityKnowledgeGraphEntityRelation]:
        with self._lock:
            return self._entityrelations.get(tenant_id, {}).get(record_id)

    def list_entityrelations(self, tenant_id: str) -> List[SecurityKnowledgeGraphEntityRelation]:
        with self._lock:
            return list(self._entityrelations.get(tenant_id, {}).values())

    def save_riskpropagationpath(self, tenant_id: str, item: SecurityKnowledgeGraphRiskPropagationPath) -> None:
        with self._lock:
            if tenant_id not in self._riskpropagationpaths:
                self._riskpropagationpaths[tenant_id] = {}
            self._riskpropagationpaths[tenant_id][item.record_id] = item

    def get_riskpropagationpath(self, tenant_id: str, record_id: str) -> Optional[SecurityKnowledgeGraphRiskPropagationPath]:
        with self._lock:
            return self._riskpropagationpaths.get(tenant_id, {}).get(record_id)

    def list_riskpropagationpaths(self, tenant_id: str) -> List[SecurityKnowledgeGraphRiskPropagationPath]:
        with self._lock:
            return list(self._riskpropagationpaths.get(tenant_id, {}).values())

    def save_federatedknowledgenode(self, tenant_id: str, item: SecurityKnowledgeGraphFederatedKnowledgeNode) -> None:
        with self._lock:
            if tenant_id not in self._federatedknowledgenodes:
                self._federatedknowledgenodes[tenant_id] = {}
            self._federatedknowledgenodes[tenant_id][item.record_id] = item

    def get_federatedknowledgenode(self, tenant_id: str, record_id: str) -> Optional[SecurityKnowledgeGraphFederatedKnowledgeNode]:
        with self._lock:
            return self._federatedknowledgenodes.get(tenant_id, {}).get(record_id)

    def list_federatedknowledgenodes(self, tenant_id: str) -> List[SecurityKnowledgeGraphFederatedKnowledgeNode]:
        with self._lock:
            return list(self._federatedknowledgenodes.get(tenant_id, {}).values())

_store_instance = SecurityKnowledgeGraphStore()

def get_store() -> SecurityKnowledgeGraphStore:
    return _store_instance
