"""Investigation Timeline Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class EventType(Enum):
    """Timeline event types"""
    ALERT = "ALERT"
    EVIDENCE = "EVIDENCE"
    ACTION = "ACTION"
    STATUS_CHANGE = "STATUS_CHANGE"
    NOTE = "NOTE"
    COMMUNICATION = "COMMUNICATION"

@dataclass
class TimelineEvent:
    """Timeline event"""
    event_id: str
    investigation_id: str
    event_type: EventType
    timestamp: datetime
    title: str
    description: str
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "investigation_id": self.investigation_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "metadata": self.metadata
        }

@dataclass
class Timeline:
    """Investigation timeline"""
    timeline_id: str
    investigation_id: str
    name: str
    events: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeline_id": self.timeline_id,
            "investigation_id": self.investigation_id,
            "name": self.name,
            "events": self.events,
            "created_at": self.created_at.isoformat()
        }