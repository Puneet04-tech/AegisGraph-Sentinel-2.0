"""
Knowledge Operating System Models
Centralized security knowledge management.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class KnowledgeType(Enum):
    """Types of knowledge."""
    FRAUD_PATTERN = "FRAUD_PATTERN"
    THREAT_INTEL = "THREAT_INTEL"
    AML_INDICATOR = "AML_INDICATOR"
    COMPLIANCE_RULE = "COMPLIANCE_RULE"
    INVESTIGATION = "INVESTIGATION"
    ATTACK_VECTOR = "ATTACK_VECTOR"
    MALWARE = "MALWARE"
    VULNERABILITY = "VULNERABILITY"
    BEST_PRACTICE = "BEST_PRACTICE"
    CASE_STUDY = "CASE_STUDY"


class KnowledgeStatus(Enum):
    """Knowledge status."""
    DRAFT = "DRAFT"
    REVIEWED = "REVIEWED"
    APPROVED = "APPROVED"
    ARCHIVED = "ARCHIVED"


class AccessLevel(Enum):
    """Access levels for knowledge."""
    PUBLIC = "PUBLIC"
    RESTRICTED = "RESTRICTED"
    CONFIDENTIAL = "CONFIDENTIAL"
    TOP_SECRET = "TOP_SECRET"


@dataclass
class KnowledgeEntry:
    """A knowledge entry in the system."""
    entry_id: str
    title: str
    content: str
    knowledge_type: KnowledgeType
    status: KnowledgeStatus = KnowledgeStatus.DRAFT
    access_level: AccessLevel = AccessLevel.PUBLIC
    tags: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    related_entries: List[str] = field(default_factory=list)
    confidence: float = 0.5
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "title": self.title,
            "content": self.content,
            "knowledge_type": self.knowledge_type.value,
            "status": self.status.value,
            "access_level": self.access_level.value,
            "tags": self.tags,
            "sources": self.sources,
            "related_entries": self.related_entries,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "metadata": self.metadata,
        }


@dataclass
class KnowledgeGraph:
    """Knowledge graph for correlations."""
    graph_id: str
    name: str
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "name": self.name,
            "nodes": self.nodes,
            "edges": self.edges,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class KnowledgeSearch:
    """Search result."""
    query: str
    results: List[KnowledgeEntry]
    relevance_scores: Dict[str, float]
    total_results: int


@dataclass
class KnowledgeRecommendation:
    """Knowledge recommendation."""
    recommendation_id: str
    entry_id: str
    reason: str
    confidence: float
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "entry_id": self.entry_id,
            "reason": self.reason,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
        }