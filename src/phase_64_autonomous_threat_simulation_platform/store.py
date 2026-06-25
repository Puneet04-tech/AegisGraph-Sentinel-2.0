import threading
from typing import Dict, List, Optional
from .models import ThreatSimulationPlatformThreatScenario, ThreatSimulationPlatformFraudSimulation, ThreatSimulationPlatformResilienceMetrics


class ThreatSimulationPlatformStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._threatscenarios: Dict[str, Dict[str, ThreatSimulationPlatformThreatScenario]] = {}
        self._fraudsimulations: Dict[str, Dict[str, ThreatSimulationPlatformFraudSimulation]] = {}
        self._resiliencemetricss: Dict[str, Dict[str, ThreatSimulationPlatformResilienceMetrics]] = {}

    def save_threatscenario(self, tenant_id: str, item: ThreatSimulationPlatformThreatScenario) -> None:
        with self._lock:
            if tenant_id not in self._threatscenarios:
                self._threatscenarios[tenant_id] = {}
            self._threatscenarios[tenant_id][item.record_id] = item

    def get_threatscenario(self, tenant_id: str, record_id: str) -> Optional[ThreatSimulationPlatformThreatScenario]:
        with self._lock:
            return self._threatscenarios.get(tenant_id, {}).get(record_id)

    def list_threatscenarios(self, tenant_id: str) -> List[ThreatSimulationPlatformThreatScenario]:
        with self._lock:
            return list(self._threatscenarios.get(tenant_id, {}).values())

    def save_fraudsimulation(self, tenant_id: str, item: ThreatSimulationPlatformFraudSimulation) -> None:
        with self._lock:
            if tenant_id not in self._fraudsimulations:
                self._fraudsimulations[tenant_id] = {}
            self._fraudsimulations[tenant_id][item.record_id] = item

    def get_fraudsimulation(self, tenant_id: str, record_id: str) -> Optional[ThreatSimulationPlatformFraudSimulation]:
        with self._lock:
            return self._fraudsimulations.get(tenant_id, {}).get(record_id)

    def list_fraudsimulations(self, tenant_id: str) -> List[ThreatSimulationPlatformFraudSimulation]:
        with self._lock:
            return list(self._fraudsimulations.get(tenant_id, {}).values())

    def save_resiliencemetrics(self, tenant_id: str, item: ThreatSimulationPlatformResilienceMetrics) -> None:
        with self._lock:
            if tenant_id not in self._resiliencemetricss:
                self._resiliencemetricss[tenant_id] = {}
            self._resiliencemetricss[tenant_id][item.record_id] = item

    def get_resiliencemetrics(self, tenant_id: str, record_id: str) -> Optional[ThreatSimulationPlatformResilienceMetrics]:
        with self._lock:
            return self._resiliencemetricss.get(tenant_id, {}).get(record_id)

    def list_resiliencemetricss(self, tenant_id: str) -> List[ThreatSimulationPlatformResilienceMetrics]:
        with self._lock:
            return list(self._resiliencemetricss.get(tenant_id, {}).values())

_store_instance = ThreatSimulationPlatformStore()

def get_store() -> ThreatSimulationPlatformStore:
    return _store_instance
