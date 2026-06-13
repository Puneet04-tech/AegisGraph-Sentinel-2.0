"""Command Center Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class MetricType(Enum):
    """Metric types"""
    SECURITY = "SECURITY"
    FRAUD = "FRAUD"
    OPERATIONAL = "OPERATIONAL"
    COMPLIANCE = "COMPLIANCE"

class ThreatLevel(Enum):
    """Threat levels"""
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    ORANGE = "ORANGE"
    RED = "RED"

@dataclass
class SecurityMetric:
    """Security metric"""
    metric_id: str
    metric_type: MetricType
    name: str
    value: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metric_id": self.metric_id,
            "metric_type": self.metric_type.value,
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat()
        }

@dataclass
class ThreatEvent:
    """Threat event"""
    event_id: str
    title: str
    severity: str
    source: str
    description: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "title": self.title,
            "severity": self.severity,
            "source": self.source,
            "description": self.description,
            "timestamp": self.timestamp.isoformat()
        }

@dataclass
class DashboardConfig:
    """Dashboard configuration"""
    config_id: str
    name: str
    widgets: List[Dict[str, Any]]
    refresh_interval: int = 60

    def to_dict(self) -> Dict[str, Any]:
        return {
            "config_id": self.config_id,
            "name": self.name,
            "widgets": self.widgets,
            "refresh_interval": self.refresh_interval
        }