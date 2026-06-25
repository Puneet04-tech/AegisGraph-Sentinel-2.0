from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class InvestigationOrchestratorInvestigationWorkflowCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    workflow_id: str = Field(..., description="workflow_id attribute")
    domain: str = Field(..., description="domain attribute")
    current_state: str = Field(..., description="current_state attribute")
    assigned_analyst: str = Field(..., description="assigned_analyst attribute")

class InvestigationOrchestratorEvidenceCorrelationCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    correlation_id: str = Field(..., description="correlation_id attribute")
    evidence_ids: List[str] = Field(..., description="evidence_ids attribute")
    score: float = Field(..., description="score attribute")
    description: str = Field(..., description="description attribute")

class InvestigationOrchestratorEscalationRecordCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    escalation_id: str = Field(..., description="escalation_id attribute")
    reason: str = Field(..., description="reason attribute")
    priority: str = Field(..., description="priority attribute")
    resolved: bool = Field(..., description="resolved attribute")
