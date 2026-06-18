"""Investigation Universe Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class InvestigationStatus(Enum):
    """Investigation status"""
    INITIAL = "INITIAL"
    COLLECTING = "COLLECTING"
    ANALYZING = "ANALYZING"
    HYPOTHESIZING = "HYPOTHESIZING"
    CORRELATING = "CORRELATING"
    CONCLUDED = "CONCLUDED"
    CLOSED = "CLOSED"

class EvidenceType(Enum):
    """Evidence types"""
    DOCUMENT = "DOCUMENT"
    NETWORK = "NETWORK"
    LOG = "LOG"
    BEHAVIORAL = "BEHAVIORAL"
    FINANCIAL = "FINANCIAL"
    COMMUNICATION = "COMMUNICATION"

class ConfidenceLevel(Enum):
    """Confidence levels for hypotheses"""
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"

@dataclass
class Evidence:
    """Investigation evidence"""
    evidence_id: str
    investigation_id: str
    evidence_type: EvidenceType
    description: str
    source: str
    collected_at: datetime = field(default_factory=datetime.utcnow)
    hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "investigation_id": self.investigation_id,
            "evidence_type": self.evidence_type.value,
            "description": self.description,
            "source": self.source,
            "collected_at": self.collected_at.isoformat(),
            "hash": self.hash,
            "metadata": self.metadata
        }

@dataclass
class Hypothesis:
    """Investigation hypothesis"""
    hypothesis_id: str
    investigation_id: str
    description: str
    confidence: ConfidenceLevel
    supporting_evidence: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "investigation_id": self.investigation_id,
            "description": self.description,
            "confidence": self.confidence.value,
            "supporting_evidence": self.supporting_evidence,
            "created_at": self.created_at.isoformat(),
            "verified": self.verified
        }

@dataclass
class Investigation:
    """AI Investigation"""
    investigation_id: str
    title: str
    description: str
    status: InvestigationStatus
    priority: int = 1
    hypotheses: List[str] = field(default_factory=list)
    evidence_count: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    concluded_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "priority": self.priority,
            "hypotheses": self.hypotheses,
            "evidence_count": self.evidence_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "concluded_at": self.concluded_at.isoformat() if self.concluded_at else None
        }

@dataclass
class Correlation:
    """Intelligence correlation"""
    correlation_id: str
    investigation_id: str
    entity_type: str
    entity_id: str
    related_entities: List[str]
    correlation_type: str
    strength: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "investigation_id": self.investigation_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "related_entities": self.related_entities,
            "correlation_type": self.correlation_type,
            "strength": self.strength
        }