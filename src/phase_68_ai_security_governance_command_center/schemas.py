from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class SecurityGovernanceCommandCenterModelGovernanceRecordCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    model_id: str = Field(..., description="model_id attribute")
    model_version: str = Field(..., description="model_version attribute")
    bias_score: float = Field(..., description="bias_score attribute")
    is_approved: bool = Field(..., description="is_approved attribute")

class SecurityGovernanceCommandCenterPromptAuditRecordCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    audit_id: str = Field(..., description="audit_id attribute")
    prompt_hash: str = Field(..., description="prompt_hash attribute")
    risk_level: str = Field(..., description="risk_level attribute")
    policy_violations: List[str] = Field(..., description="policy_violations attribute")

class SecurityGovernanceCommandCenterRiskMonitorStateCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    state_id: str = Field(..., description="state_id attribute")
    total_governed_models: int = Field(..., description="total_governed_models attribute")
    anomalies_count: int = Field(..., description="anomalies_count attribute")
    last_checked: str = Field(..., description="last_checked attribute")
