import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import ThreatSimulationPlatformThreatScenario, ThreatSimulationPlatformFraudSimulation, ThreatSimulationPlatformResilienceMetrics
from .store import ThreatSimulationPlatformStore


class ThreatSimulationPlatformService:
    def __init__(self, store: ThreatSimulationPlatformStore):
        self.store = store
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, tenant_id: str, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "timestamp": datetime.utcnow(),
            "tenant_id": tenant_id,
            "action": action,
            "details": details
        })

    def create_threatscenario(self, tenant_id: str, record_id: str, scenario_id: str, scenario_type: str, steps: List[str], target_assets: List[str]) -> ThreatSimulationPlatformThreatScenario:
        item = ThreatSimulationPlatformThreatScenario(
            record_id=record_id, tenant_id=tenant_id, scenario_id=scenario_id, scenario_type=scenario_type, steps=steps, target_assets=target_assets,
            created_at=datetime.utcnow()
        )
        self.store.save_threatscenario(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'ThreatScenario'.upper()}", {"record_id": record_id})
        return item

    def get_threatscenario(self, tenant_id: str, record_id: str) -> Optional[ThreatSimulationPlatformThreatScenario]:
        return self.store.get_threatscenario(tenant_id, record_id)

    def list_threatscenarios(self, tenant_id: str) -> List[ThreatSimulationPlatformThreatScenario]:
        return self.store.list_threatscenarios(tenant_id)

    def create_fraudsimulation(self, tenant_id: str, record_id: str, simulation_id: str, campaign_type: str, detection_rate: float, status: str) -> ThreatSimulationPlatformFraudSimulation:
        item = ThreatSimulationPlatformFraudSimulation(
            record_id=record_id, tenant_id=tenant_id, simulation_id=simulation_id, campaign_type=campaign_type, detection_rate=detection_rate, status=status,
            created_at=datetime.utcnow()
        )
        self.store.save_fraudsimulation(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'FraudSimulation'.upper()}", {"record_id": record_id})
        return item

    def get_fraudsimulation(self, tenant_id: str, record_id: str) -> Optional[ThreatSimulationPlatformFraudSimulation]:
        return self.store.get_fraudsimulation(tenant_id, record_id)

    def list_fraudsimulations(self, tenant_id: str) -> List[ThreatSimulationPlatformFraudSimulation]:
        return self.store.list_fraudsimulations(tenant_id)

    def create_resiliencemetrics(self, tenant_id: str, record_id: str, metrics_id: str, scenario_id: str, breach_probability: float, mitigation_score: float) -> ThreatSimulationPlatformResilienceMetrics:
        item = ThreatSimulationPlatformResilienceMetrics(
            record_id=record_id, tenant_id=tenant_id, metrics_id=metrics_id, scenario_id=scenario_id, breach_probability=breach_probability, mitigation_score=mitigation_score,
            created_at=datetime.utcnow()
        )
        self.store.save_resiliencemetrics(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'ResilienceMetrics'.upper()}", {"record_id": record_id})
        return item

    def get_resiliencemetrics(self, tenant_id: str, record_id: str) -> Optional[ThreatSimulationPlatformResilienceMetrics]:
        return self.store.get_resiliencemetrics(tenant_id, record_id)

    def list_resiliencemetricss(self, tenant_id: str) -> List[ThreatSimulationPlatformResilienceMetrics]:
        return self.store.list_resiliencemetricss(tenant_id)

def get_service() -> ThreatSimulationPlatformService:
    from .store import get_store
    return ThreatSimulationPlatformService(get_store())
