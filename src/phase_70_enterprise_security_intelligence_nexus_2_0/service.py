import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import SecurityIntelligenceNexusGlobalIntelligenceHubState, SecurityIntelligenceNexusUnifiedAnalyticsReport, SecurityIntelligenceNexusIntelligenceRoute
from .store import SecurityIntelligenceNexusStore


class SecurityIntelligenceNexusService:
    def __init__(self, store: SecurityIntelligenceNexusStore):
        self.store = store
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, tenant_id: str, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "timestamp": datetime.utcnow(),
            "tenant_id": tenant_id,
            "action": action,
            "details": details
        })

    def create_globalintelligencehubstate(self, tenant_id: str, record_id: str, hub_id: str, connected_domains: List[str], ingestion_rate: float, is_healthy: bool) -> SecurityIntelligenceNexusGlobalIntelligenceHubState:
        item = SecurityIntelligenceNexusGlobalIntelligenceHubState(
            record_id=record_id, tenant_id=tenant_id, hub_id=hub_id, connected_domains=connected_domains, ingestion_rate=ingestion_rate, is_healthy=is_healthy,
            created_at=datetime.utcnow()
        )
        self.store.save_globalintelligencehubstate(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'GlobalIntelligenceHubState'.upper()}", {"record_id": record_id})
        return item

    def get_globalintelligencehubstate(self, tenant_id: str, record_id: str) -> Optional[SecurityIntelligenceNexusGlobalIntelligenceHubState]:
        return self.store.get_globalintelligencehubstate(tenant_id, record_id)

    def list_globalintelligencehubstates(self, tenant_id: str) -> List[SecurityIntelligenceNexusGlobalIntelligenceHubState]:
        return self.store.list_globalintelligencehubstates(tenant_id)

    def create_unifiedanalyticsreport(self, tenant_id: str, record_id: str, report_id: str, generated_by: str, domain_coverage: Dict[str, float], threat_count: int) -> SecurityIntelligenceNexusUnifiedAnalyticsReport:
        item = SecurityIntelligenceNexusUnifiedAnalyticsReport(
            record_id=record_id, tenant_id=tenant_id, report_id=report_id, generated_by=generated_by, domain_coverage=domain_coverage, threat_count=threat_count,
            created_at=datetime.utcnow()
        )
        self.store.save_unifiedanalyticsreport(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'UnifiedAnalyticsReport'.upper()}", {"record_id": record_id})
        return item

    def get_unifiedanalyticsreport(self, tenant_id: str, record_id: str) -> Optional[SecurityIntelligenceNexusUnifiedAnalyticsReport]:
        return self.store.get_unifiedanalyticsreport(tenant_id, record_id)

    def list_unifiedanalyticsreports(self, tenant_id: str) -> List[SecurityIntelligenceNexusUnifiedAnalyticsReport]:
        return self.store.list_unifiedanalyticsreports(tenant_id)

    def create_intelligenceroute(self, tenant_id: str, record_id: str, route_id: str, source_domain: str, target_domain: str, priority: str) -> SecurityIntelligenceNexusIntelligenceRoute:
        item = SecurityIntelligenceNexusIntelligenceRoute(
            record_id=record_id, tenant_id=tenant_id, route_id=route_id, source_domain=source_domain, target_domain=target_domain, priority=priority,
            created_at=datetime.utcnow()
        )
        self.store.save_intelligenceroute(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'IntelligenceRoute'.upper()}", {"record_id": record_id})
        return item

    def get_intelligenceroute(self, tenant_id: str, record_id: str) -> Optional[SecurityIntelligenceNexusIntelligenceRoute]:
        return self.store.get_intelligenceroute(tenant_id, record_id)

    def list_intelligenceroutes(self, tenant_id: str) -> List[SecurityIntelligenceNexusIntelligenceRoute]:
        return self.store.list_intelligenceroutes(tenant_id)

def get_service() -> SecurityIntelligenceNexusService:
    from .store import get_store
    return SecurityIntelligenceNexusService(get_store())
