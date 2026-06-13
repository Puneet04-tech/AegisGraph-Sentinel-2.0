"""
Fraud Investigation Knowledge Hub - Data Models

Centralized intelligence and investigation knowledge platform.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class InvestigationType(str, Enum):
    """Investigation types."""
    FRAUD = "FRAUD"
    CYBER = "CYBER"
    COMPLIANCE = "COMPLIANCE"
    INSIDER = "INSIDER"
    THREAT_INTEL = "THREAT_INTEL"
    GENERAL = "GENERAL"


class EntityType(str, Enum):
    """Entity types."""
    PERSON = "PERSON"
    ORGANIZATION = "ORGANIZATION"
    ACCOUNT = "ACCOUNT"
    TRANSACTION = "TRANSACTION"
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    PHONE = "PHONE"
    EMAIL = "EMAIL"


class InvestigationTemplate(BaseModel):
    """Investigation template."""
    template_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    investigation_type: InvestigationType
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    required_data: List[str] = Field(default_factory=list)
    estimated_hours: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    usage_count: int = 0
    tags: List[str] = Field(default_factory=list)


class InvestigationRecord(BaseModel):
    """Investigation record."""
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    investigation_type: InvestigationType
    status: str = "OPEN"
    priority: str = "MEDIUM"
    assigned_to: Optional[str] = None
    related_entities: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    linked_investigations: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: Optional[datetime] = None


class KnowledgeEntry(BaseModel):
    """Knowledge entry."""
    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content: str
    entity_type: EntityType
    tags: List[str] = Field(default_factory=list)
    related_records: List[str] = Field(default_factory=list)
    source: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EntityKnowledge(BaseModel):
    """Entity knowledge graph entry."""
    entity_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: EntityType
    entity_value: str
    attributes: Dict[str, Any] = Field(default_factory=dict)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score: float = 0.0
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SearchResult(BaseModel):
    """Search result."""
    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query: str
    result_type: str
    title: str
    snippet: str
    relevance_score: float = 0.0
    record_id: Optional[str] = None
    entity_id: Optional[str] = None


class KnowledgeMetrics(BaseModel):
    """Knowledge hub metrics."""
    total_records: int = 0
    total_templates: int = 0
    total_entities: int = 0
    total_knowledge_entries: int = 0
    records_by_type: Dict[str, int] = Field(default_factory=dict)
    recent_activity: List[Dict[str, Any]] = Field(default_factory=list)
