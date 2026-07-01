from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class UniversalRiskIntelligenceGraphRecord:
    record_id: str
    tenant_id: str
    name: str
    status: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UniversalRiskIntelligenceGraphEvent:
    event_id: str
    tenant_id: str
    record_id: str
    event_type: str
    severity: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UniversalRiskIntelligenceGraphAlert:
    alert_id: str
    tenant_id: str
    title: str
    severity: str
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
