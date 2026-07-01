import threading
from typing import Dict, List, Optional
from .models import SecurityIntelligenceNexusGlobalIntelligenceHubState, SecurityIntelligenceNexusUnifiedAnalyticsReport, SecurityIntelligenceNexusIntelligenceRoute


class SecurityIntelligenceNexusStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._globalintelligencehubstates: Dict[str, Dict[str, SecurityIntelligenceNexusGlobalIntelligenceHubState]] = {}
        self._unifiedanalyticsreports: Dict[str, Dict[str, SecurityIntelligenceNexusUnifiedAnalyticsReport]] = {}
        self._intelligenceroutes: Dict[str, Dict[str, SecurityIntelligenceNexusIntelligenceRoute]] = {}

    def save_globalintelligencehubstate(self, tenant_id: str, item: SecurityIntelligenceNexusGlobalIntelligenceHubState) -> None:
        with self._lock:
            if tenant_id not in self._globalintelligencehubstates:
                self._globalintelligencehubstates[tenant_id] = {}
            self._globalintelligencehubstates[tenant_id][item.record_id] = item

    def get_globalintelligencehubstate(self, tenant_id: str, record_id: str) -> Optional[SecurityIntelligenceNexusGlobalIntelligenceHubState]:
        with self._lock:
            return self._globalintelligencehubstates.get(tenant_id, {}).get(record_id)

    def list_globalintelligencehubstates(self, tenant_id: str) -> List[SecurityIntelligenceNexusGlobalIntelligenceHubState]:
        with self._lock:
            return list(self._globalintelligencehubstates.get(tenant_id, {}).values())

    def save_unifiedanalyticsreport(self, tenant_id: str, item: SecurityIntelligenceNexusUnifiedAnalyticsReport) -> None:
        with self._lock:
            if tenant_id not in self._unifiedanalyticsreports:
                self._unifiedanalyticsreports[tenant_id] = {}
            self._unifiedanalyticsreports[tenant_id][item.record_id] = item

    def get_unifiedanalyticsreport(self, tenant_id: str, record_id: str) -> Optional[SecurityIntelligenceNexusUnifiedAnalyticsReport]:
        with self._lock:
            return self._unifiedanalyticsreports.get(tenant_id, {}).get(record_id)

    def list_unifiedanalyticsreports(self, tenant_id: str) -> List[SecurityIntelligenceNexusUnifiedAnalyticsReport]:
        with self._lock:
            return list(self._unifiedanalyticsreports.get(tenant_id, {}).values())

    def save_intelligenceroute(self, tenant_id: str, item: SecurityIntelligenceNexusIntelligenceRoute) -> None:
        with self._lock:
            if tenant_id not in self._intelligenceroutes:
                self._intelligenceroutes[tenant_id] = {}
            self._intelligenceroutes[tenant_id][item.record_id] = item

    def get_intelligenceroute(self, tenant_id: str, record_id: str) -> Optional[SecurityIntelligenceNexusIntelligenceRoute]:
        with self._lock:
            return self._intelligenceroutes.get(tenant_id, {}).get(record_id)

    def list_intelligenceroutes(self, tenant_id: str) -> List[SecurityIntelligenceNexusIntelligenceRoute]:
        with self._lock:
            return list(self._intelligenceroutes.get(tenant_id, {}).values())

_store_instance = SecurityIntelligenceNexusStore()

def get_store() -> SecurityIntelligenceNexusStore:
    return _store_instance
