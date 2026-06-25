from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class SecurityKnowledgeGraphEntityRelationCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    relation_id: str = Field(..., description="relation_id attribute")
    source_entity: str = Field(..., description="source_entity attribute")
    target_entity: str = Field(..., description="target_entity attribute")
    relation_type: str = Field(..., description="relation_type attribute")
    confidence: float = Field(..., description="confidence attribute")

class SecurityKnowledgeGraphRiskPropagationPathCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    path_id: str = Field(..., description="path_id attribute")
    nodes: List[str] = Field(..., description="nodes attribute")
    total_risk: float = Field(..., description="total_risk attribute")
    mitigation_status: str = Field(..., description="mitigation_status attribute")

class SecurityKnowledgeGraphFederatedKnowledgeNodeCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    node_id: str = Field(..., description="node_id attribute")
    source_domain: str = Field(..., description="source_domain attribute")
    sync_status: str = Field(..., description="sync_status attribute")
