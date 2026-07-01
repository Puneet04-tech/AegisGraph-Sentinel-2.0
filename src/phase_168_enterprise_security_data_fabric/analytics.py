from typing import Dict, Any, List
from .store import EnterpriseSecurityDataFabricStore


class EnterpriseSecurityDataFabricAnalytics:
    def __init__(self, store: EnterpriseSecurityDataFabricStore):
        self.store = store

    def compute_kpis(self, tenant_id: str) -> Dict[str, Any]:
        records = self.store.list_records(tenant_id)
        alerts = self.store.list_alerts(tenant_id)
        active_records = [r for r in records if r.status == "ACTIVE"]
        active_alerts = [a for a in alerts if a.is_active]
        critical_alerts = [a for a in alerts if a.severity == "CRITICAL"]
        return {
            "total_records": len(records),
            "active_records": len(active_records),
            "total_alerts": len(alerts),
            "active_alerts": len(active_alerts),
            "critical_alerts": len(critical_alerts),
            "health_score": round((len(active_records) / max(len(records), 1)) * 100, 2),
            "alert_rate": round(len(active_alerts) / max(len(records), 1), 4),
        }
