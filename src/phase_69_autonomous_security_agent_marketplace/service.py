import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import SecurityAgentMarketplaceAgentRegistration, SecurityAgentMarketplaceOrchestrationSession, SecurityAgentMarketplaceAgentCapability
from .store import SecurityAgentMarketplaceStore


class SecurityAgentMarketplaceService:
    def __init__(self, store: SecurityAgentMarketplaceStore):
        self.store = store
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, tenant_id: str, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "timestamp": datetime.utcnow(),
            "tenant_id": tenant_id,
            "action": action,
            "details": details
        })

    def create_agentregistration(self, tenant_id: str, record_id: str, agent_id: str, agent_name: str, capabilities: List[str], status: str) -> SecurityAgentMarketplaceAgentRegistration:
        item = SecurityAgentMarketplaceAgentRegistration(
            record_id=record_id, tenant_id=tenant_id, agent_id=agent_id, agent_name=agent_name, capabilities=capabilities, status=status,
            created_at=datetime.utcnow()
        )
        self.store.save_agentregistration(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'AgentRegistration'.upper()}", {"record_id": record_id})
        return item

    def get_agentregistration(self, tenant_id: str, record_id: str) -> Optional[SecurityAgentMarketplaceAgentRegistration]:
        return self.store.get_agentregistration(tenant_id, record_id)

    def list_agentregistrations(self, tenant_id: str) -> List[SecurityAgentMarketplaceAgentRegistration]:
        return self.store.list_agentregistrations(tenant_id)

    def create_orchestrationsession(self, tenant_id: str, record_id: str, session_id: str, active_agents: List[str], task_status: str, messages_exchanged: int) -> SecurityAgentMarketplaceOrchestrationSession:
        item = SecurityAgentMarketplaceOrchestrationSession(
            record_id=record_id, tenant_id=tenant_id, session_id=session_id, active_agents=active_agents, task_status=task_status, messages_exchanged=messages_exchanged,
            created_at=datetime.utcnow()
        )
        self.store.save_orchestrationsession(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'OrchestrationSession'.upper()}", {"record_id": record_id})
        return item

    def get_orchestrationsession(self, tenant_id: str, record_id: str) -> Optional[SecurityAgentMarketplaceOrchestrationSession]:
        return self.store.get_orchestrationsession(tenant_id, record_id)

    def list_orchestrationsessions(self, tenant_id: str) -> List[SecurityAgentMarketplaceOrchestrationSession]:
        return self.store.list_orchestrationsessions(tenant_id)

    def create_agentcapability(self, tenant_id: str, record_id: str, capability_id: str, name: str, cost_per_token: float, governance_level: str) -> SecurityAgentMarketplaceAgentCapability:
        item = SecurityAgentMarketplaceAgentCapability(
            record_id=record_id, tenant_id=tenant_id, capability_id=capability_id, name=name, cost_per_token=cost_per_token, governance_level=governance_level,
            created_at=datetime.utcnow()
        )
        self.store.save_agentcapability(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'AgentCapability'.upper()}", {"record_id": record_id})
        return item

    def get_agentcapability(self, tenant_id: str, record_id: str) -> Optional[SecurityAgentMarketplaceAgentCapability]:
        return self.store.get_agentcapability(tenant_id, record_id)

    def list_agentcapabilitys(self, tenant_id: str) -> List[SecurityAgentMarketplaceAgentCapability]:
        return self.store.list_agentcapabilitys(tenant_id)

def get_service() -> SecurityAgentMarketplaceService:
    from .store import get_store
    return SecurityAgentMarketplaceService(get_store())
