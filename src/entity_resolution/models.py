"""
Data models for Entity Resolution and Knowledge Graph Engine.

Core models:
    Entity: Represents a fraud-related entity (account, device, IP, etc.)
    EntityRelationship: Represents a relationship between two entities
    FraudCluster: Represents a detected fraud ring cluster
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Any
import uuid


class EntityType(str, Enum):
    """Types of entities that can be tracked in the knowledge graph."""
    ACCOUNT = "ACCOUNT"
    DEVICE = "DEVICE"
    IP_ADDRESS = "IP_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    EMAIL = "EMAIL"
    WALLET = "WALLET"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    CARD = "CARD"
    TRANSACTION = "TRANSACTION"
    LOCATION = "LOCATION"


class RelationshipType(str, Enum):
    """Types of relationships between entities."""
    SHARED_DEVICE = "SHARED_DEVICE"
    SHARED_IP = "SHARED_IP"
    SHARED_PHONE = "SHARED_PHONE"
    SHARED_EMAIL = "SHARED_EMAIL"
    WALLET_OWNER = "WALLET_OWNER"
    WALLET_BENEFICIARY = "WALLET_BENEFICIARY"
    TRANSFER_FROM = "TRANSFER_FROM"
    TRANSFER_TO = "TRANSFER_TO"
    SAME_PERSON = "SAME_PERSON"
    FAMILY_MEMBER = "FAMILY_MEMBER"
    BUSINESS_ASSOCIATE = "BUSINESS_ASSOCIATE"
    CASH_OUT = "CASH_OUT"
    MULE_ACCOUNT = "MULE_ACCOUNT"


@dataclass
class Entity:
    """Represents a fraud-related entity in the knowledge graph.
    
    Entities are the nodes in the knowledge graph. They can represent
    accounts, devices, IP addresses, phone numbers, emails, wallets, etc.
    
    Attributes:
        id: Unique identifier for the entity
        entity_type: Type of entity (ACCOUNT, DEVICE, IP_ADDRESS, etc.)
        value: The actual value (e.g., account number, device ID)
        attributes: Additional attributes for the entity
        risk_score: Current risk score (0.0 to 1.0)
        tags: Set of tags for categorization
        created_at: Timestamp when entity was created
        updated_at: Timestamp when entity was last updated
        metadata: Additional metadata dictionary
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: EntityType = EntityType.ACCOUNT
    value: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    tags: Set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate entity after initialization."""
        if not self.value:
            raise ValueError("Entity value cannot be empty")
        if not isinstance(self.entity_type, EntityType):
            raise TypeError(f"entity_type must be EntityType, got {type(self.entity_type)}")
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError(f"risk_score must be between 0.0 and 1.0, got {self.risk_score}")
    
    def update_risk_score(self, new_score: float) -> None:
        """Update the entity's risk score.
        
        Args:
            new_score: New risk score between 0.0 and 1.0
            
        Raises:
            ValueError: If score is out of range
        """
        if not 0.0 <= new_score <= 1.0:
            raise ValueError(f"risk_score must be between 0.0 and 1.0, got {new_score}")
        self.risk_score = new_score
        self.updated_at = datetime.now(timezone.utc)
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to the entity.
        
        Args:
            tag: Tag to add
        """
        self.tags.add(tag)
        self.updated_at = datetime.now(timezone.utc)
    
    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the entity.
        
        Args:
            tag: Tag to remove
        """
        self.tags.discard(tag)
        self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entity to dictionary representation.
        
        Returns:
            Dictionary representation of the entity
        """
        return {
            "id": self.id,
            "entity_type": self.entity_type.value,
            "value": self.value,
            "attributes": self.attributes,
            "risk_score": self.risk_score,
            "tags": list(self.tags),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Entity":
        """Create an Entity from a dictionary representation.
        
        Args:
            data: Dictionary containing entity data
            
        Returns:
            Entity instance
        """
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        elif created_at is None:
            created_at = datetime.now(timezone.utc)
            
        updated_at = data.get("updated_at")
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        elif updated_at is None:
            updated_at = datetime.now(timezone.utc)
        
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            entity_type=EntityType(data.get("entity_type", "ACCOUNT")),
            value=data.get("value", ""),
            attributes=data.get("attributes", {}),
            risk_score=data.get("risk_score", 0.0),
            tags=set(data.get("tags", [])),
            created_at=created_at,
            updated_at=updated_at,
            metadata=data.get("metadata", {}),
        )


@dataclass
class EntityRelationship:
    """Represents a relationship between two entities.
    
    Relationships are the edges in the knowledge graph. They capture
    how entities are connected (e.g., shared device, shared IP).
    
    Attributes:
        source_id: ID of the source entity
        target_id: ID of the target entity
        relationship_type: Type of relationship
        confidence_score: Confidence in the relationship (0.0 to 1.0)
        evidence: Evidence supporting the relationship
        created_at: Timestamp when relationship was created
        metadata: Additional metadata
    """
    source_id: str
    target_id: str
    relationship_type: RelationshipType = RelationshipType.SHARED_DEVICE
    confidence_score: float = 0.5
    evidence: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate relationship after initialization."""
        if not self.source_id:
            raise ValueError("source_id cannot be empty")
        if not self.target_id:
            raise ValueError("target_id cannot be empty")
        if not isinstance(self.relationship_type, RelationshipType):
            raise TypeError(f"relationship_type must be RelationshipType, got {type(self.relationship_type)}")
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError(f"confidence_score must be between 0.0 and 1.0, got {self.confidence_score}")
    
    def add_evidence(self, evidence: str) -> None:
        """Add evidence supporting this relationship.
        
        Args:
            evidence: Evidence string to add
        """
        self.evidence.append(evidence)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert relationship to dictionary representation.
        
        Returns:
            Dictionary representation of the relationship
        """
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship_type": self.relationship_type.value,
            "confidence_score": self.confidence_score,
            "evidence": self.evidence,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EntityRelationship":
        """Create an EntityRelationship from a dictionary.
        
        Args:
            data: Dictionary containing relationship data
            
        Returns:
            EntityRelationship instance
        """
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        elif created_at is None:
            created_at = datetime.now(timezone.utc)
        
        return cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            relationship_type=RelationshipType(data.get("relationship_type", "SHARED_DEVICE")),
            confidence_score=data.get("confidence_score", 0.5),
            evidence=data.get("evidence", []),
            created_at=created_at,
            metadata=data.get("metadata", {}),
        )


@dataclass
class FraudCluster:
    """Represents a detected fraud ring cluster.
    
    A fraud cluster is a group of entities that are connected through
    various relationships and have been identified as a potential fraud ring.
    
    Attributes:
        cluster_id: Unique identifier for the cluster
        entity_ids: Set of entity IDs in this cluster
        risk_score: Aggregate risk score for the cluster
        created_at: Timestamp when cluster was created
        updated_at: Timestamp when cluster was last updated
        tags: Set of tags for the cluster
        metadata: Additional metadata
    """
    cluster_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_ids: Set[str] = field(default_factory=set)
    risk_score: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate cluster after initialization."""
        if not self.entity_ids:
            raise ValueError("FraudCluster must contain at least one entity")
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError(f"risk_score must be between 0.0 and 1.0, got {self.risk_score}")
    
    def add_entity(self, entity_id: str) -> None:
        """Add an entity to the cluster.
        
        Args:
            entity_id: ID of the entity to add
        """
        self.entity_ids.add(entity_id)
        self.updated_at = datetime.now(timezone.utc)
    
    def remove_entity(self, entity_id: str) -> None:
        """Remove an entity from the cluster.
        
        Args:
            entity_id: ID of the entity to remove
        """
        if entity_id in self.entity_ids:
            self.entity_ids.discard(entity_id)
            self.updated_at = datetime.now(timezone.utc)
    
    def update_risk_score(self, new_score: float) -> None:
        """Update the cluster's risk score.
        
        Args:
            new_score: New risk score between 0.0 and 1.0
            
        Raises:
            ValueError: If score is out of range
        """
        if not 0.0 <= new_score <= 1.0:
            raise ValueError(f"risk_score must be between 0.0 and 1.0, got {new_score}")
        self.risk_score = new_score
        self.updated_at = datetime.now(timezone.utc)
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to the cluster.
        
        Args:
            tag: Tag to add
        """
        self.tags.add(tag)
        self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert cluster to dictionary representation.
        
        Returns:
            Dictionary representation of the cluster
        """
        return {
            "cluster_id": self.cluster_id,
            "entity_ids": list(self.entity_ids),
            "risk_score": self.risk_score,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "tags": list(self.tags),
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FraudCluster":
        """Create a FraudCluster from a dictionary.
        
        Args:
            data: Dictionary containing cluster data
            
        Returns:
            FraudCluster instance
        """
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        elif created_at is None:
            created_at = datetime.now(timezone.utc)
            
        updated_at = data.get("updated_at")
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        elif updated_at is None:
            updated_at = datetime.now(timezone.utc)
        
        return cls(
            cluster_id=data.get("cluster_id", str(uuid.uuid4())),
            entity_ids=set(data.get("entity_ids", [])),
            risk_score=data.get("risk_score", 0.0),
            created_at=created_at,
            updated_at=updated_at,
            tags=set(data.get("tags", [])),
            metadata=data.get("metadata", {}),
        )