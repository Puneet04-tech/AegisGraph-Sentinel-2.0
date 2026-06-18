"""Alert Correlation Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5

class AlertStatus(Enum):
    """Alert status"""
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"

@dataclass
class Alert:
    """Security alert"""
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    source: str
    status: AlertStatus = AlertStatus.NEW
    tags: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    linked_incidents: List[str] = field(default_factory=list)
    deduplicated: bool = False
    deduplicated_by: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "source": self.source,
            "status": self.status.value,
            "tags": self.tags,
            "indicators": self.indicators,
            "linked_incidents": self.linked_incidents,
            "deduplicated": self.deduplicated,
            "deduplicated_by": self.deduplicated_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

@dataclass
class AlertGroup:
    """Group of correlated alerts"""
    group_id: str
    name: str
    description: str
    alert_ids: List[str]
    primary_alert_id: str
    correlation_score: float
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "name": self.name,
            "description": self.description,
            "alert_ids": self.alert_ids,
            "primary_alert_id": self.primary_alert_id,
            "correlation_score": self.correlation_score,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class SuppressionRule:
    """Alert suppression rule"""
    rule_id: str
    name: str
    description: str
    conditions: Dict[str, Any]
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "conditions": self.conditions,
            "enabled": self.enabled
        }

@dataclass
class CorrelationRule:
    """Alert correlation rule"""
    rule_id: str
    name: str
    description: str
    conditions: Dict[str, Any]
    group_template: str
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "conditions": self.conditions,
            "group_template": self.group_template,
            "enabled": self.enabled
        }