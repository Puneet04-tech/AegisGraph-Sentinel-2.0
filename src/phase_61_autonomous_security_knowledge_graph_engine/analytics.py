from typing import Dict, Any
from .store import SecurityKnowledgeGraphStore


class SecurityKnowledgeGraphAnalytics:
    def __init__(self, store: SecurityKnowledgeGraphStore):
        self.store = store

    def compute_kpis(self, tenant_id: str) -> Dict[str, Any]:
        list1 = self.store.list_entityrelations(tenant_id)
        list2 = self.store.list_riskpropagationpaths(tenant_id)
        list3 = self.store.list_federatedknowledgenodes(tenant_id)
        
        c1 = len(list1)
        c2 = len(list2)
        c3 = len(list3)
        total = c1 + c2 + c3
        
        return {
            "total_items": total,
            "count_entityrelation": c1,
            "count_riskpropagationpath": c2,
            "count_federatedknowledgenode": c3,
            "health_score": round((c1 + c2) / max(total, 1) * 100, 2),
            "activity_rate": round(c3 / max(c1 + c2, 1), 4)
        }
