from typing import Dict, Any
from .store import SecurityIntelligenceNexusStore


class SecurityIntelligenceNexusAnalytics:
    def __init__(self, store: SecurityIntelligenceNexusStore):
        self.store = store

    def compute_kpis(self, tenant_id: str) -> Dict[str, Any]:
        list1 = self.store.list_globalintelligencehubstates(tenant_id)
        list2 = self.store.list_unifiedanalyticsreports(tenant_id)
        list3 = self.store.list_intelligenceroutes(tenant_id)
        
        c1 = len(list1)
        c2 = len(list2)
        c3 = len(list3)
        total = c1 + c2 + c3
        
        return {
            "total_items": total,
            "count_globalintelligencehubstate": c1,
            "count_unifiedanalyticsreport": c2,
            "count_intelligenceroute": c3,
            "health_score": round((c1 + c2) / max(total, 1) * 100, 2),
            "activity_rate": round(c3 / max(c1 + c2, 1), 4)
        }
