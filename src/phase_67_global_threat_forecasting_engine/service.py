import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import ThreatForecastingEngineThreatForecast, ThreatForecastingEngineTrendIndicator, ThreatForecastingEngineCampaignPrediction
from .store import ThreatForecastingEngineStore


class ThreatForecastingEngineService:
    def __init__(self, store: ThreatForecastingEngineStore):
        self.store = store
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, tenant_id: str, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "timestamp": datetime.utcnow(),
            "tenant_id": tenant_id,
            "action": action,
            "details": details
        })

    def create_threatforecast(self, tenant_id: str, record_id: str, forecast_id: str, predicted_threat_type: str, likelihood: float, target_sectors: List[str]) -> ThreatForecastingEngineThreatForecast:
        item = ThreatForecastingEngineThreatForecast(
            record_id=record_id, tenant_id=tenant_id, forecast_id=forecast_id, predicted_threat_type=predicted_threat_type, likelihood=likelihood, target_sectors=target_sectors,
            created_at=datetime.utcnow()
        )
        self.store.save_threatforecast(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'ThreatForecast'.upper()}", {"record_id": record_id})
        return item

    def get_threatforecast(self, tenant_id: str, record_id: str) -> Optional[ThreatForecastingEngineThreatForecast]:
        return self.store.get_threatforecast(tenant_id, record_id)

    def list_threatforecasts(self, tenant_id: str) -> List[ThreatForecastingEngineThreatForecast]:
        return self.store.list_threatforecasts(tenant_id)

    def create_trendindicator(self, tenant_id: str, record_id: str, indicator_id: str, metric_name: str, trend_direction: str, change_percentage: float) -> ThreatForecastingEngineTrendIndicator:
        item = ThreatForecastingEngineTrendIndicator(
            record_id=record_id, tenant_id=tenant_id, indicator_id=indicator_id, metric_name=metric_name, trend_direction=trend_direction, change_percentage=change_percentage,
            created_at=datetime.utcnow()
        )
        self.store.save_trendindicator(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'TrendIndicator'.upper()}", {"record_id": record_id})
        return item

    def get_trendindicator(self, tenant_id: str, record_id: str) -> Optional[ThreatForecastingEngineTrendIndicator]:
        return self.store.get_trendindicator(tenant_id, record_id)

    def list_trendindicators(self, tenant_id: str) -> List[ThreatForecastingEngineTrendIndicator]:
        return self.store.list_trendindicators(tenant_id)

    def create_campaignprediction(self, tenant_id: str, record_id: str, prediction_id: str, actor_group: str, predicted_date: str, confidence_level: float) -> ThreatForecastingEngineCampaignPrediction:
        item = ThreatForecastingEngineCampaignPrediction(
            record_id=record_id, tenant_id=tenant_id, prediction_id=prediction_id, actor_group=actor_group, predicted_date=predicted_date, confidence_level=confidence_level,
            created_at=datetime.utcnow()
        )
        self.store.save_campaignprediction(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'CampaignPrediction'.upper()}", {"record_id": record_id})
        return item

    def get_campaignprediction(self, tenant_id: str, record_id: str) -> Optional[ThreatForecastingEngineCampaignPrediction]:
        return self.store.get_campaignprediction(tenant_id, record_id)

    def list_campaignpredictions(self, tenant_id: str) -> List[ThreatForecastingEngineCampaignPrediction]:
        return self.store.list_campaignpredictions(tenant_id)

def get_service() -> ThreatForecastingEngineService:
    from .store import get_store
    return ThreatForecastingEngineService(get_store())
