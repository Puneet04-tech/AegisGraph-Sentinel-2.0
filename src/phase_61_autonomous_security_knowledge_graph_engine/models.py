from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class SecurityKnowledgeGraphEntityRelation:
    record_id: str
    tenant_id: str
    relation_id: str
    source_entity: str
    target_entity: str
    relation_type: str
    confidence: float
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityKnowledgeGraphRiskPropagationPath:
    record_id: str
    tenant_id: str
    path_id: str
    nodes: List[str]
    total_risk: float
    mitigation_status: str
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityKnowledgeGraphFederatedKnowledgeNode:
    record_id: str
    tenant_id: str
    node_id: str
    source_domain: str
    sync_status: str
    created_at: datetime = field(default_factory=datetime.utcnow)
