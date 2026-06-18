"""Security Metamodel Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class EntityCategory(Enum):
    """Entity categories"""
    THREAT = "THREAT"
    ASSET = "ASSET"
    VULNERABILITY = "VULNERABILITY"
    CONTROL = "CONTROL"
    CAMPAIGN = "CAMPAIGN"
    INVESTIGATION = "INVESTIGATION"
    ACTOR = "ACTOR"

class RelationshipType(Enum):
    """Relationship types between entities"""
    IDENTIFIES = "IDENTIFIES"
    EXPLOITS = "EXPLOITS"
    MITIGATES = "MITIGATES"
    PART_OF = "PART_OF"
    RELATED_TO = "RELATED_TO"
    CAUSED_BY = "CAUSED_BY"
    TARGETS = "TARGETS"

@dataclass
class EntityDefinition:
    """Universal entity definition"""
    entity_id: str
    name: str
    category: EntityCategory
    description: str
    properties: Dict[str, Any] = field(default_factory=dict)
    schema: Dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "properties": self.properties,
            "schema": self.schema,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class SemanticRelation:
    """Semantic relationship between entities"""
    relation_id: str
    source_entity_id: str
    target_entity_id: str
    relationship_type: RelationshipType
    metadata: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relation_id": self.relation_id,
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "relationship_type": self.relationship_type.value,
            "metadata": self.metadata,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class OntologyClass:
    """Ontology class definition"""
    class_id: str
    name: str
    parent_class_id: Optional[str]
    properties: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "class_id": self.class_id,
            "name": self.name,
            "parent_class_id": self.parent_class_id,
            "properties": self.properties,
            "description": self.description
        }

@dataclass
class KnowledgeMapping:
    """Knowledge mapping between concepts"""
    mapping_id: str
    source_concept: str
    target_concept: str
    mapping_type: str
    bidirectional: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mapping_id": self.mapping_id,
            "source_concept": self.source_concept,
            "target_concept": self.target_concept,
            "mapping_type": self.mapping_type,
            "bidirectional": self.bidirectional
        }