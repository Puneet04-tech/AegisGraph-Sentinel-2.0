"""Fraud Pattern Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class PatternType(Enum):
    """Fraud pattern types"""
    STRUCTURAL = "STRUCTURAL"
    BEHAVIORAL = "BEHAVIORAL"
    TRANSACTIONAL = "TRANSACTIONAL"
    NETWORK = "NETWORK"

class DetectionStatus(Enum):
    """Detection status"""
    DETECTED = "DETECTED"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INVESTIGATING = "INVESTIGATING"

@dataclass
class Pattern:
    """Fraud pattern definition"""
    pattern_id: str
    name: str
    pattern_type: PatternType
    description: str
    rules: List[Dict[str, Any]]
    severity: str
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "pattern_type": self.pattern_type.value,
            "description": self.description,
            "rules": self.rules,
            "severity": self.severity,
            "enabled": self.enabled
        }

@dataclass
class Detection:
    """Pattern detection record"""
    detection_id: str
    pattern_id: str
    entity_id: str
    status: DetectionStatus
    confidence: float
    detected_at: datetime = field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "pattern_id": self.pattern_id,
            "entity_id": self.entity_id,
            "status": self.status.value,
            "confidence": self.confidence,
            "detected_at": self.detected_at.isoformat(),
            "details": self.details
        }