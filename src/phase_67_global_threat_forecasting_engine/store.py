import threading
from typing import Dict, List, Optional
from .models import ThreatForecastingEngineThreatForecast, ThreatForecastingEngineTrendIndicator, ThreatForecastingEngineCampaignPrediction


class ThreatForecastingEngineStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._threatforecasts: Dict[str, Dict[str, ThreatForecastingEngineThreatForecast]] = {}
        self._trendindicators: Dict[str, Dict[str, ThreatForecastingEngineTrendIndicator]] = {}
        self._campaignpredictions: Dict[str, Dict[str, ThreatForecastingEngineCampaignPrediction]] = {}

    def save_threatforecast(self, tenant_id: str, item: ThreatForecastingEngineThreatForecast) -> None:
        with self._lock:
            if tenant_id not in self._threatforecasts:
                self._threatforecasts[tenant_id] = {}
            self._threatforecasts[tenant_id][item.record_id] = item

    def get_threatforecast(self, tenant_id: str, record_id: str) -> Optional[ThreatForecastingEngineThreatForecast]:
        with self._lock:
            return self._threatforecasts.get(tenant_id, {}).get(record_id)

    def list_threatforecasts(self, tenant_id: str) -> List[ThreatForecastingEngineThreatForecast]:
        with self._lock:
            return list(self._threatforecasts.get(tenant_id, {}).values())

    def save_trendindicator(self, tenant_id: str, item: ThreatForecastingEngineTrendIndicator) -> None:
        with self._lock:
            if tenant_id not in self._trendindicators:
                self._trendindicators[tenant_id] = {}
            self._trendindicators[tenant_id][item.record_id] = item

    def get_trendindicator(self, tenant_id: str, record_id: str) -> Optional[ThreatForecastingEngineTrendIndicator]:
        with self._lock:
            return self._trendindicators.get(tenant_id, {}).get(record_id)

    def list_trendindicators(self, tenant_id: str) -> List[ThreatForecastingEngineTrendIndicator]:
        with self._lock:
            return list(self._trendindicators.get(tenant_id, {}).values())

    def save_campaignprediction(self, tenant_id: str, item: ThreatForecastingEngineCampaignPrediction) -> None:
        with self._lock:
            if tenant_id not in self._campaignpredictions:
                self._campaignpredictions[tenant_id] = {}
            self._campaignpredictions[tenant_id][item.record_id] = item

    def get_campaignprediction(self, tenant_id: str, record_id: str) -> Optional[ThreatForecastingEngineCampaignPrediction]:
        with self._lock:
            return self._campaignpredictions.get(tenant_id, {}).get(record_id)

    def list_campaignpredictions(self, tenant_id: str) -> List[ThreatForecastingEngineCampaignPrediction]:
        with self._lock:
            return list(self._campaignpredictions.get(tenant_id, {}).values())

_store_instance = ThreatForecastingEngineStore()

def get_store() -> ThreatForecastingEngineStore:
    return _store_instance
