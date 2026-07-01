from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class SecurityIntelligenceNexusGlobalIntelligenceHubState:
    record_id: str
    tenant_id: str
    hub_id: str
    connected_domains: List[str]
    ingestion_rate: float
    is_healthy: bool
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityIntelligenceNexusUnifiedAnalyticsReport:
    record_id: str
    tenant_id: str
    report_id: str
    generated_by: str
    domain_coverage: Dict[str, float]
    threat_count: int
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityIntelligenceNexusIntelligenceRoute:
    record_id: str
    tenant_id: str
    route_id: str
    source_domain: str
    target_domain: str
    priority: str
    created_at: datetime = field(default_factory=datetime.utcnow)
