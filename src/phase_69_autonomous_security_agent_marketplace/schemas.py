from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class SecurityAgentMarketplaceAgentRegistrationCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    agent_id: str = Field(..., description="agent_id attribute")
    agent_name: str = Field(..., description="agent_name attribute")
    capabilities: List[str] = Field(..., description="capabilities attribute")
    status: str = Field(..., description="status attribute")

class SecurityAgentMarketplaceOrchestrationSessionCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    session_id: str = Field(..., description="session_id attribute")
    active_agents: List[str] = Field(..., description="active_agents attribute")
    task_status: str = Field(..., description="task_status attribute")
    messages_exchanged: int = Field(..., description="messages_exchanged attribute")

class SecurityAgentMarketplaceAgentCapabilityCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    capability_id: str = Field(..., description="capability_id attribute")
    name: str = Field(..., description="name attribute")
    cost_per_token: float = Field(..., description="cost_per_token attribute")
    governance_level: str = Field(..., description="governance_level attribute")
