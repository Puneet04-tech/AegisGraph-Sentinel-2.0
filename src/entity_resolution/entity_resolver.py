"""
Entity Resolution Engine for linking related fraud entities.

Provides:
    EntityResolver: Engine for linking accounts, devices, IPs, phones, emails, and wallets
    get_entity_resolver: Singleton getter for the entity resolver
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
import logging
import uuid

from .models import Entity, EntityRelationship, EntityType, RelationshipType
from .store import EntityStore, get_entity_store

logger = logging.getLogger(__name__)


@dataclass
class LinkRequest:
    """Request to link two entities."""
    source_entity_id: Optional[str] = None
    source_entity_type: Optional[EntityType] = None
    source_value: Optional[str] = None
    target_entity_id: Optional[str] = None
    target_entity_type: Optional[EntityType] = None
    target_value: Optional[str] = None
    relationship_type: RelationshipType = RelationshipType.SHARED_DEVICE
    confidence_score: float = 0.5
    evidence: Optional[List[str]] = None
    attributes: Optional[Dict[str, Any]] = None


@dataclass
class LinkResult:
    """Result of linking two entities."""
    relationship: EntityRelationship
    source_entity: Entity
    target_entity: Entity
    is_new_relationship: bool
    is_new_source_entity: bool
    is_new_target_entity: bool


class EntityResolver:
    """Entity Resolution Engine for linking fraud entities.
    
    This engine is responsible for:
    - Linking accounts sharing devices
    - Linking accounts sharing IP addresses
    - Linking accounts sharing phone numbers
    - Linking accounts sharing emails
    - Linking wallet relationships
    - Calculating relationship confidence
    
    Attributes:
        store: Entity store for persistence
        confidence_weights: Weights for calculating relationship confidence
    """
    
    # Confidence weights for different relationship types
    DEFAULT_CONFIDENCE_WEIGHTS = {
        RelationshipType.SHARED_DEVICE: 0.85,
        RelationshipType.SHARED_IP: 0.75,
        RelationshipType.SHARED_PHONE: 0.80,
        RelationshipType.SHARED_EMAIL: 0.70,
        RelationshipType.WALLET_OWNER: 0.90,
        RelationshipType.WALLET_BENEFICIARY: 0.85,
        RelationshipType.TRANSFER_FROM: 0.80,
        RelationshipType.TRANSFER_TO: 0.80,
        RelationshipType.SAME_PERSON: 0.95,
        RelationshipType.FAMILY_MEMBER: 0.75,
        RelationshipType.BUSINESS_ASSOCIATE: 0.60,
        RelationshipType.CASH_OUT: 0.70,
        RelationshipType.MULE_ACCOUNT: 0.95,
    }
    
    def __init__(self, store: Optional[EntityStore] = None):
        """Initialize the entity resolver.
        
        Args:
            store: Optional entity store (creates singleton if not provided)
        """
        self._store = store or get_entity_store()
        self._confidence_weights = self.DEFAULT_CONFIDENCE_WEIGHTS.copy()
    
    def _get_or_create_entity(self, entity_id: Optional[str], entity_type: EntityType, value: str, attributes: Optional[Dict[str, Any]] = None) -> Tuple[Entity, bool]:
        """Get an existing entity or create a new one.
        
        Args:
            entity_id: Optional existing entity ID
            entity_type: Type of the entity
            value: Value of the entity
            attributes: Optional additional attributes
            
        Returns:
            Tuple of (entity, is_new)
        """
        is_new = False
        
        # Try to find existing entity
        if entity_id:
            entity = self._store.get_entity(entity_id)
            if entity:
                return entity, False
        
        # Try to find by type and value
        entity = self._store.get_entity_by_type_value(entity_type, value)
        if entity:
            return entity, False
        
        # Create new entity
        entity = Entity(
            id=entity_id or str(uuid.uuid4()),
            entity_type=entity_type,
            value=value,
            attributes=attributes or {},
        )
        self._store.store_entity(entity)
        is_new = True
        
        logger.debug(f"Created new entity {entity.id} of type {entity_type.value}")
        return entity, is_new
    
    def _calculate_confidence(self, relationship_type: RelationshipType, evidence: List[str], attributes: Dict[str, Any]) -> float:
        """Calculate confidence score for a relationship.
        
        Args:
            relationship_type: Type of relationship
            evidence: List of evidence strings
            attributes: Additional attributes
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = self._confidence_weights.get(relationship_type, 0.5)
        
        # Adjust based on evidence count
        evidence_factor = min(len(evidence) * 0.05, 0.2)
        
        # Adjust based on attributes
        attribute_factor = 0.0
        if attributes:
            if attributes.get("verified", False):
                attribute_factor += 0.1
            if attributes.get("cross_checked", False):
                attribute_factor += 0.1
            if attributes.get("multiple_sources", False):
                attribute_factor += 0.1
        
        # Calculate final confidence
        confidence = min(base_confidence + evidence_factor + attribute_factor, 1.0)
        return confidence
    
    def link_entities(self, request: LinkRequest) -> LinkResult:
        """Link two entities together with a relationship.
        
        Args:
            request: Link request containing entity information
            
        Returns:
            LinkResult with the relationship and entities
        """
        # Validate request
        if not request.source_value and not request.source_entity_id:
            raise ValueError("Either source_value or source_entity_id must be provided")
        if not request.target_value and not request.target_entity_id:
            raise ValueError("Either target_value or target_entity_id must be provided")
        if not request.source_entity_type and not request.target_entity_type:
            raise ValueError("At least one entity type must be provided")
        
        # Determine entity types
        source_type = request.source_entity_type or EntityType.ACCOUNT
        target_type = request.target_entity_type or EntityType.ACCOUNT
        
        # Get or create source entity
        source_entity, is_new_source = self._get_or_create_entity(
            request.source_entity_id,
            source_type,
            request.source_value,
            request.attributes,
        )
        
        # Get or create target entity
        target_entity, is_new_target = self._get_or_create_entity(
            request.target_entity_id,
            target_type,
            request.target_value,
            request.attributes,
        )
        
        # Calculate confidence
        evidence = request.evidence or []
        attributes = request.attributes or {}
        confidence = self._calculate_confidence(request.relationship_type, evidence, attributes)
        
        # Check if relationship already exists
        existing_rel = self._store.get_relationship(source_entity.id, target_entity.id, request.relationship_type)
        is_new_relationship = existing_rel is None
        
        # Create or update relationship
        if existing_rel:
            # Update existing relationship
            existing_rel.confidence_score = confidence
            if evidence:
                existing_rel.evidence.extend(evidence)
            relationship = existing_rel
        else:
            # Create new relationship
            relationship = EntityRelationship(
                source_id=source_entity.id,
                target_id=target_entity.id,
                relationship_type=request.relationship_type,
                confidence_score=confidence,
                evidence=evidence,
                metadata=attributes,
            )
        
        self._store.store_relationship(relationship)
        
        logger.info(f"Linked entity {source_entity.id} to {target_entity.id} with relationship {request.relationship_type.value}")
        
        return LinkResult(
            relationship=relationship,
            source_entity=source_entity,
            target_entity=target_entity,
            is_new_relationship=is_new_relationship,
            is_new_source_entity=is_new_source,
            is_new_target_entity=is_new_target,
        )
    
    def link_device(self, account_id: str, device_id: str, confidence: float = 0.85) -> LinkResult:
        """Link an account to a device.
        
        Args:
            account_id: Account identifier
            device_id: Device identifier
            confidence: Relationship confidence (0.0 to 1.0)
            
        Returns:
            LinkResult with the relationship
        """
        request = LinkRequest(
            source_entity_id=account_id,
            source_entity_type=EntityType.ACCOUNT,
            source_value=account_id,
            target_entity_id=device_id,
            target_entity_type=EntityType.DEVICE,
            target_value=device_id,
            relationship_type=RelationshipType.SHARED_DEVICE,
            confidence_score=confidence,
            evidence=[f"Account {account_id} associated with device {device_id}"],
        )
        return self.link_entities(request)
    
    def link_ip_address(self, account_id: str, ip_address: str, confidence: float = 0.75) -> LinkResult:
        """Link an account to an IP address.
        
        Args:
            account_id: Account identifier
            ip_address: IP address
            confidence: Relationship confidence (0.0 to 1.0)
            
        Returns:
            LinkResult with the relationship
        """
        request = LinkRequest(
            source_entity_id=account_id,
            source_entity_type=EntityType.ACCOUNT,
            source_value=account_id,
            target_entity_id=ip_address,
            target_entity_type=EntityType.IP_ADDRESS,
            target_value=ip_address,
            relationship_type=RelationshipType.SHARED_IP,
            confidence_score=confidence,
            evidence=[f"Account {account_id} accessed from IP {ip_address}"],
        )
        return self.link_entities(request)
    
    def link_phone_number(self, account_id: str, phone_number: str, confidence: float = 0.80) -> LinkResult:
        """Link an account to a phone number.
        
        Args:
            account_id: Account identifier
            phone_number: Phone number
            confidence: Relationship confidence (0.0 to 1.0)
            
        Returns:
            LinkResult with the relationship
        """
        request = LinkRequest(
            source_entity_id=account_id,
            source_entity_type=EntityType.ACCOUNT,
            source_value=account_id,
            target_entity_id=phone_number,
            target_entity_type=EntityType.PHONE_NUMBER,
            target_value=phone_number,
            relationship_type=RelationshipType.SHARED_PHONE,
            confidence_score=confidence,
            evidence=[f"Account {account_id} associated with phone {phone_number}"],
        )
        return self.link_entities(request)
    
    def link_email(self, account_id: str, email: str, confidence: float = 0.70) -> LinkResult:
        """Link an account to an email address.
        
        Args:
            account_id: Account identifier
            email: Email address
            confidence: Relationship confidence (0.0 to 1.0)
            
        Returns:
            LinkResult with the relationship
        """
        request = LinkRequest(
            source_entity_id=account_id,
            source_entity_type=EntityType.ACCOUNT,
            source_value=account_id,
            target_entity_id=email,
            target_entity_type=EntityType.EMAIL,
            target_value=email,
            relationship_type=RelationshipType.SHARED_EMAIL,
            confidence_score=confidence,
            evidence=[f"Account {account_id} registered with email {email}"],
        )
        return self.link_entities(request)
    
    def link_wallet(self, account_id: str, wallet_address: str, is_owner: bool = True, confidence: float = 0.90) -> LinkResult:
        """Link an account to a wallet.
        
        Args:
            account_id: Account identifier
            wallet_address: Wallet address
            is_owner: True if account owns the wallet, False if beneficiary
            confidence: Relationship confidence (0.0 to 1.0)
            
        Returns:
            LinkResult with the relationship
        """
        rel_type = RelationshipType.WALLET_OWNER if is_owner else RelationshipType.WALLET_BENEFICIARY
        request = LinkRequest(
            source_entity_id=account_id,
            source_entity_type=EntityType.ACCOUNT,
            source_value=account_id,
            target_entity_id=wallet_address,
            target_entity_type=EntityType.WALLET,
            target_value=wallet_address,
            relationship_type=rel_type,
            confidence_score=confidence,
            evidence=[f"Account {account_id} {'owns' if is_owner else 'beneficiary of'} wallet {wallet_address}"],
        )
        return self.link_entities(request)
    
    def link_transaction(self, from_account: str, to_account: str, transaction_id: str, amount: float, confidence: float = 0.80) -> Tuple[LinkResult, LinkResult]:
        """Link accounts involved in a transaction.
        
        Args:
            from_account: Source account identifier
            to_account: Target account identifier
            transaction_id: Transaction identifier
            amount: Transaction amount
            confidence: Relationship confidence (0.0 to 1.0)
            
        Returns:
            Tuple of (from_relationship, to_relationship)
        """
        # Create transaction entity
        transaction_entity = Entity(
            entity_type=EntityType.TRANSACTION,
            value=transaction_id,
            attributes={"amount": amount},
        )
        self._store.store_entity(transaction_entity)
        
        # Link from account to transaction
        from_rel = self.link_entities(LinkRequest(
            source_entity_id=from_account,
            source_entity_type=EntityType.ACCOUNT,
            source_value=from_account,
            target_entity_id=transaction_entity.id,
            target_entity_type=EntityType.TRANSACTION,
            target_value=transaction_id,
            relationship_type=RelationshipType.TRANSFER_FROM,
            confidence_score=confidence,
            evidence=[f"Transaction {transaction_id} of {amount} from {from_account}"],
        ))
        
        # Link transaction to to account
        to_rel = self.link_entities(LinkRequest(
            source_entity_id=transaction_entity.id,
            source_entity_type=EntityType.TRANSACTION,
            source_value=transaction_id,
            target_entity_id=to_account,
            target_entity_type=EntityType.ACCOUNT,
            target_value=to_account,
            relationship_type=RelationshipType.TRANSFER_TO,
            confidence_score=confidence,
            evidence=[f"Transaction {transaction_id} of {amount} to {to_account}"],
        ))
        
        return from_rel, to_rel
    
    def get_entity_network(self, entity_id: str, max_depth: int = 3) -> Dict[str, Any]:
        """Get the network of entities connected to a given entity.
        
        Args:
            entity_id: ID of the entity
            max_depth: Maximum depth to traverse
            
        Returns:
            Dictionary with network information
        """
        network = {
            "root_entity_id": entity_id,
            "entities": [],
            "relationships": [],
            "depth": 0,
        }
        
        visited = {entity_id}
        current_level = {entity_id}
        
        for depth in range(max_depth):
            next_level = set()
            
            for current_id in current_level:
                entity = self._store.get_entity(current_id)
                if entity:
                    network["entities"].append(entity.to_dict())
                
                relationships = self._store.get_relationships_for_entity(current_id)
                for rel in relationships:
                    network["relationships"].append(rel.to_dict())
                    
                    # Add connected entities
                    if rel.source_id == current_id:
                        connected_id = rel.target_id
                    else:
                        connected_id = rel.source_id
                    
                    if connected_id not in visited:
                        next_level.add(connected_id)
                        visited.add(connected_id)
            
            current_level = next_level
            if not current_level:
                break
        
        network["depth"] = depth + 1
        network["total_entities"] = len(network["entities"])
        network["total_relationships"] = len(network["relationships"])
        
        return network
    
    def find_similar_entities(self, entity_id: str, threshold: float = 0.7) -> List[Entity]:
        """Find entities similar to the given entity based on shared connections.
        
        Args:
            entity_id: ID of the entity
            threshold: Minimum relationship confidence threshold
            
        Returns:
            List of similar entities
        """
        similar = {}
        
        # Get direct connections
        connections = self._store.get_relationships_for_entity(entity_id)
        
        for rel in connections:
            if rel.confidence_score < threshold:
                continue
            
            connected_id = rel.target_id if rel.source_id == entity_id else rel.source_id
            
            # Get connections of connected entity
            second_degree = self._store.get_relationships_for_entity(connected_id)
            for second_rel in second_degree:
                if second_rel.confidence_score < threshold:
                    continue
                
                other_id = second_rel.target_id if second_rel.source_id == connected_id else second_rel.source_id
                
                if other_id != entity_id and other_id not in {r.source_id for r in connections} and other_id not in {r.target_id for r in connections}:
                    if other_id not in similar:
                        similar[other_id] = {
                            "entity": None,
                            "shared_connections": [],
                            "avg_confidence": 0.0,
                        }
                    similar[other_id]["shared_connections"].append(connected_id)
        
        # Calculate average confidence and fetch entities
        result = []
        for other_id, info in similar.items():
            # Calculate average confidence
            confs = []
            for conn_id in info["shared_connections"]:
                rels = self._store.get_relationships_for_entity(other_id)
                for rel in rels:
                    if rel.source_id == entity_id or rel.target_id == entity_id:
                        confs.append(rel.confidence_score)
                        break
            
            if confs:
                info["avg_confidence"] = sum(confs) / len(confs)
            
            entity = self._store.get_entity(other_id)
            if entity:
                info["entity"] = entity
                result.append(entity)
        
        return sorted(result, key=lambda e: similar[e.id]["avg_confidence"], reverse=True)
    
    def unlink_entities(self, source_id: str, target_id: str, relationship_type: Optional[RelationshipType] = None) -> bool:
        """Unlink two entities by removing the relationship.
        
        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            relationship_type: Optional specific relationship type to remove
            
        Returns:
            True if relationship was removed, False if not found
        """
        if relationship_type:
            rel_id = f"{source_id}:{target_id}:{relationship_type.value}"
            with self._store._relationship_lock:
                if rel_id in self._store._relationships:
                    del self._store._relationships[rel_id]
                    logger.info(f"Unlinked {source_id} from {target_id} with relationship {relationship_type.value}")
                    return True
        else:
            # Remove all relationships between entities
            removed = False
            with self._store._relationship_lock:
                to_remove = []
                for rel_id, rel in self._store._relationships.items():
                    if (rel.source_id == source_id and rel.target_id == target_id) or \
                       (rel.source_id == target_id and rel.target_id == source_id):
                        to_remove.append(rel_id)
                
                for rel_id in to_remove:
                    del self._store._relationships[rel_id]
                    removed = True
            
            if removed:
                logger.info(f"Unlinked {source_id} from {target_id}")
            return removed
        
        return False


# Global singleton instance
_entity_resolver: Optional[EntityResolver] = None
_resolver_lock = object()


def get_entity_resolver(store: Optional[EntityStore] = None) -> EntityResolver:
    """Get or create the singleton EntityResolver instance.
    
    Args:
        store: Optional entity store
        
    Returns:
        The singleton EntityResolver instance
    """
    global _entity_resolver
    
    if _entity_resolver is None:
        _entity_resolver = EntityResolver(store=store)
    return _entity_resolver