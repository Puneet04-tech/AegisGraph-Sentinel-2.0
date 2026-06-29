import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import SecurityDigitalTwinDigitalTwinState, SecurityDigitalTwinRiskVisualizationNode, SecurityDigitalTwinForecastingScenario
from .store import SecurityDigitalTwinStore

class SecurityDigitalTwinService:
    def __init__(self, store: SecurityDigitalTwinStore):
        self.store = store
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, tenant_id: str, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "timestamp": datetime.utcnow(),
            "tenant_id": tenant_id,
            "action": action,
            "details": details
        })

    def create_digitaltwinstate(self, tenant_id: str, record_id: str, state_id: str, entity_id: str, posture_score: float, anomaly_detected: bool) -> SecurityDigitalTwinDigitalTwinState:
        item = SecurityDigitalTwinDigitalTwinState(
            record_id=record_id, tenant_id=tenant_id, state_id=state_id, entity_id=entity_id, posture_score=posture_score, anomaly_detected=anomaly_detected,
            created_at=datetime.utcnow()
        )
        self.store.save_digitaltwinstate(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'DigitalTwinState'.upper()}", {"record_id": record_id})
        return item

    def get_digitaltwinstate(self, tenant_id: str, record_id: str) -> Optional[SecurityDigitalTwinDigitalTwinState]:
        return self.store.get_digitaltwinstate(tenant_id, record_id)

    def list_digitaltwinstates(self, tenant_id: str) -> List[SecurityDigitalTwinDigitalTwinState]:
        return self.store.list_digitaltwinstates(tenant_id)

    def create_riskvisualizationnode(self, tenant_id: str, record_id: str, node_id: str, asset_name: str, risk_level: str, x_y_coordinates: List[float]) -> SecurityDigitalTwinRiskVisualizationNode:
        item = SecurityDigitalTwinRiskVisualizationNode(
            record_id=record_id, tenant_id=tenant_id, node_id=node_id, asset_name=asset_name, risk_level=risk_level, x_y_coordinates=x_y_coordinates,
            created_at=datetime.utcnow()
        )
        self.store.save_riskvisualizationnode(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'RiskVisualizationNode'.upper()}", {"record_id": record_id})
        return item

    def get_riskvisualizationnode(self, tenant_id: str, record_id: str) -> Optional[SecurityDigitalTwinRiskVisualizationNode]:
        return self.store.get_riskvisualizationnode(tenant_id, record_id)

    def list_riskvisualizationnodes(self, tenant_id: str) -> List[SecurityDigitalTwinRiskVisualizationNode]:
        return self.store.list_riskvisualizationnodes(tenant_id)

    def create_forecastingscenario(self, tenant_id: str, record_id: str, scenario_id: str, predicted_impact: str, forecasting_accuracy: float, is_critical: bool) -> SecurityDigitalTwinForecastingScenario:
        item = SecurityDigitalTwinForecastingScenario(
            record_id=record_id, tenant_id=tenant_id, scenario_id=scenario_id, predicted_impact=predicted_impact, forecasting_accuracy=forecasting_accuracy, is_critical=is_critical,
            created_at=datetime.utcnow()
        )
        self.store.save_forecastingscenario(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'ForecastingScenario'.upper()}", {"record_id": record_id})
        return item

    def get_forecastingscenario(self, tenant_id: str, record_id: str) -> Optional[SecurityDigitalTwinForecastingScenario]:
        return self.store.get_forecastingscenario(tenant_id, record_id)

    def list_forecastingscenarios(self, tenant_id: str) -> List[SecurityDigitalTwinForecastingScenario]:
        return self.store.list_forecastingscenarios(tenant_id)

def get_service() -> SecurityDigitalTwinService:
    from .store import get_store
    return SecurityDigitalTwinService(get_store())
