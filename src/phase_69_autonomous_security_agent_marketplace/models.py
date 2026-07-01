from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class SecurityAgentMarketplaceAgentRegistration:
    record_id: str
    tenant_id: str
    agent_id: str
    agent_name: str
    capabilities: List[str]
    status: str
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityAgentMarketplaceOrchestrationSession:
    record_id: str
    tenant_id: str
    session_id: str
    active_agents: List[str]
    task_status: str
    messages_exchanged: int
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityAgentMarketplaceAgentCapability:
    record_id: str
    tenant_id: str
    capability_id: str
    name: str
    cost_per_token: float
    governance_level: str
    created_at: datetime = field(default_factory=datetime.utcnow)
