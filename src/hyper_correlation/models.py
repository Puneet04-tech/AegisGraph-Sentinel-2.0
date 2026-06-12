"""Hyper Correlation Models"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any

class CorrelationType(Enum):
    TEMPORAL = "TEMPORAL"
    SPATIAL = "SPATIAL"

@dataclass
class CorrelationEvent:
    event_id: str
    correlation_type: CorrelationType
    score: float
    def to_dict(self) -> Dict[str, Any]:
        return {"event_id": self.event_id, "type": self.correlation_type.value}
