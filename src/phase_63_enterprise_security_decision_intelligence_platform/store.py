import threading
from typing import Dict, List, Optional
from .models import DecisionIntelligencePlatformDecisionContext, DecisionIntelligencePlatformExplainabilityReport, DecisionIntelligencePlatformRiskRecommendation


class DecisionIntelligencePlatformStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._decisioncontexts: Dict[str, Dict[str, DecisionIntelligencePlatformDecisionContext]] = {}
        self._explainabilityreports: Dict[str, Dict[str, DecisionIntelligencePlatformExplainabilityReport]] = {}
        self._riskrecommendations: Dict[str, Dict[str, DecisionIntelligencePlatformRiskRecommendation]] = {}

    def save_decisioncontext(self, tenant_id: str, item: DecisionIntelligencePlatformDecisionContext) -> None:
        with self._lock:
            if tenant_id not in self._decisioncontexts:
                self._decisioncontexts[tenant_id] = {}
            self._decisioncontexts[tenant_id][item.record_id] = item

    def get_decisioncontext(self, tenant_id: str, record_id: str) -> Optional[DecisionIntelligencePlatformDecisionContext]:
        with self._lock:
            return self._decisioncontexts.get(tenant_id, {}).get(record_id)

    def list_decisioncontexts(self, tenant_id: str) -> List[DecisionIntelligencePlatformDecisionContext]:
        with self._lock:
            return list(self._decisioncontexts.get(tenant_id, {}).values())

    def save_explainabilityreport(self, tenant_id: str, item: DecisionIntelligencePlatformExplainabilityReport) -> None:
        with self._lock:
            if tenant_id not in self._explainabilityreports:
                self._explainabilityreports[tenant_id] = {}
            self._explainabilityreports[tenant_id][item.record_id] = item

    def get_explainabilityreport(self, tenant_id: str, record_id: str) -> Optional[DecisionIntelligencePlatformExplainabilityReport]:
        with self._lock:
            return self._explainabilityreports.get(tenant_id, {}).get(record_id)

    def list_explainabilityreports(self, tenant_id: str) -> List[DecisionIntelligencePlatformExplainabilityReport]:
        with self._lock:
            return list(self._explainabilityreports.get(tenant_id, {}).values())

    def save_riskrecommendation(self, tenant_id: str, item: DecisionIntelligencePlatformRiskRecommendation) -> None:
        with self._lock:
            if tenant_id not in self._riskrecommendations:
                self._riskrecommendations[tenant_id] = {}
            self._riskrecommendations[tenant_id][item.record_id] = item

    def get_riskrecommendation(self, tenant_id: str, record_id: str) -> Optional[DecisionIntelligencePlatformRiskRecommendation]:
        with self._lock:
            return self._riskrecommendations.get(tenant_id, {}).get(record_id)

    def list_riskrecommendations(self, tenant_id: str) -> List[DecisionIntelligencePlatformRiskRecommendation]:
        with self._lock:
            return list(self._riskrecommendations.get(tenant_id, {}).values())

_store_instance = DecisionIntelligencePlatformStore()

def get_store() -> DecisionIntelligencePlatformStore:
    return _store_instance
