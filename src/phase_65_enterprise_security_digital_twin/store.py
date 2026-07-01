import threading
from typing import Dict, List, Optional
from .models import SecurityDigitalTwinDigitalTwinState, SecurityDigitalTwinRiskVisualizationNode, SecurityDigitalTwinForecastingScenario

class SecurityDigitalTwinStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._digitaltwinstates: Dict[str, Dict[str, SecurityDigitalTwinDigitalTwinState]] = {}
        self._riskvisualizationnodes: Dict[str, Dict[str, SecurityDigitalTwinRiskVisualizationNode]] = {}
        self._forecastingscenarios: Dict[str, Dict[str, SecurityDigitalTwinForecastingScenario]] = {}

    def save_digitaltwinstate(self, tenant_id: str, item: SecurityDigitalTwinDigitalTwinState) -> None:
        with self._lock:
            if tenant_id not in self._digitaltwinstates:
                self._digitaltwinstates[tenant_id] = {}
            self._digitaltwinstates[tenant_id][item.record_id] = item

    def get_digitaltwinstate(self, tenant_id: str, record_id: str) -> Optional[SecurityDigitalTwinDigitalTwinState]:
        with self._lock:
            return self._digitaltwinstates.get(tenant_id, {}).get(record_id)

    def list_digitaltwinstates(self, tenant_id: str) -> List[SecurityDigitalTwinDigitalTwinState]:
        with self._lock:
            return list(self._digitaltwinstates.get(tenant_id, {}).values())

    def save_riskvisualizationnode(self, tenant_id: str, item: SecurityDigitalTwinRiskVisualizationNode) -> None:
        with self._lock:
            if tenant_id not in self._riskvisualizationnodes:
                self._riskvisualizationnodes[tenant_id] = {}
            self._riskvisualizationnodes[tenant_id][item.record_id] = item

    def get_riskvisualizationnode(self, tenant_id: str, record_id: str) -> Optional[SecurityDigitalTwinRiskVisualizationNode]:
        with self._lock:
            return self._riskvisualizationnodes.get(tenant_id, {}).get(record_id)

    def list_riskvisualizationnodes(self, tenant_id: str) -> List[SecurityDigitalTwinRiskVisualizationNode]:
        with self._lock:
            return list(self._riskvisualizationnodes.get(tenant_id, {}).values())

    def save_forecastingscenario(self, tenant_id: str, item: SecurityDigitalTwinForecastingScenario) -> None:
        with self._lock:
            if tenant_id not in self._forecastingscenarios:
                self._forecastingscenarios[tenant_id] = {}
            self._forecastingscenarios[tenant_id][item.record_id] = item

    def get_forecastingscenario(self, tenant_id: str, record_id: str) -> Optional[SecurityDigitalTwinForecastingScenario]:
        with self._lock:
            return self._forecastingscenarios.get(tenant_id, {}).get(record_id)

    def list_forecastingscenarios(self, tenant_id: str) -> List[SecurityDigitalTwinForecastingScenario]:
        with self._lock:
            return list(self._forecastingscenarios.get(tenant_id, {}).values())

_store_instance = SecurityDigitalTwinStore()

def get_store() -> SecurityDigitalTwinStore:
    return _store_instance
