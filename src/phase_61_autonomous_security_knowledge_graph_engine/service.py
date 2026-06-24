import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import SecurityKnowledgeGraphEntityRelation, SecurityKnowledgeGraphRiskPropagationPath, SecurityKnowledgeGraphFederatedKnowledgeNode
from .store import SecurityKnowledgeGraphStore


class SecurityKnowledgeGraphService:
    def __init__(self, store: SecurityKnowledgeGraphStore):
        self.store = store
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, tenant_id: str, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "timestamp": datetime.utcnow(),
            "tenant_id": tenant_id,
            "action": action,
            "details": details
        })

    def create_entityrelation(self, tenant_id: str, record_id: str, relation_id: str, source_entity: str, target_entity: str, relation_type: str, confidence: float) -> SecurityKnowledgeGraphEntityRelation:
        item = SecurityKnowledgeGraphEntityRelation(
            record_id=record_id, tenant_id=tenant_id, relation_id=relation_id, source_entity=source_entity, target_entity=target_entity, relation_type=relation_type, confidence=confidence,
            created_at=datetime.utcnow()
        )
        self.store.save_entityrelation(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'EntityRelation'.upper()}", {"record_id": record_id})
        return item

    def get_entityrelation(self, tenant_id: str, record_id: str) -> Optional[SecurityKnowledgeGraphEntityRelation]:
        return self.store.get_entityrelation(tenant_id, record_id)

    def list_entityrelations(self, tenant_id: str) -> List[SecurityKnowledgeGraphEntityRelation]:
        return self.store.list_entityrelations(tenant_id)

    def create_riskpropagationpath(self, tenant_id: str, record_id: str, path_id: str, nodes: List[str], total_risk: float, mitigation_status: str) -> SecurityKnowledgeGraphRiskPropagationPath:
        item = SecurityKnowledgeGraphRiskPropagationPath(
            record_id=record_id, tenant_id=tenant_id, path_id=path_id, nodes=nodes, total_risk=total_risk, mitigation_status=mitigation_status,
            created_at=datetime.utcnow()
        )
        self.store.save_riskpropagationpath(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'RiskPropagationPath'.upper()}", {"record_id": record_id})
        return item

    def get_riskpropagationpath(self, tenant_id: str, record_id: str) -> Optional[SecurityKnowledgeGraphRiskPropagationPath]:
        return self.store.get_riskpropagationpath(tenant_id, record_id)

    def list_riskpropagationpaths(self, tenant_id: str) -> List[SecurityKnowledgeGraphRiskPropagationPath]:
        return self.store.list_riskpropagationpaths(tenant_id)

    def create_federatedknowledgenode(self, tenant_id: str, record_id: str, node_id: str, source_domain: str, sync_status: str) -> SecurityKnowledgeGraphFederatedKnowledgeNode:
        item = SecurityKnowledgeGraphFederatedKnowledgeNode(
            record_id=record_id, tenant_id=tenant_id, node_id=node_id, source_domain=source_domain, sync_status=sync_status,
            created_at=datetime.utcnow()
        )
        self.store.save_federatedknowledgenode(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'FederatedKnowledgeNode'.upper()}", {"record_id": record_id})
        return item

    def get_federatedknowledgenode(self, tenant_id: str, record_id: str) -> Optional[SecurityKnowledgeGraphFederatedKnowledgeNode]:
        return self.store.get_federatedknowledgenode(tenant_id, record_id)

    def list_federatedknowledgenodes(self, tenant_id: str) -> List[SecurityKnowledgeGraphFederatedKnowledgeNode]:
        return self.store.list_federatedknowledgenodes(tenant_id)

def get_service() -> SecurityKnowledgeGraphService:
    from .store import get_store
    return SecurityKnowledgeGraphService(get_store())
