"""Security Metamodel Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from .models import (
    EntityDefinition, SemanticRelation, OntologyClass, KnowledgeMapping,
    EntityCategory, RelationshipType
)

class SecurityMetamodelService:
    """Enterprise Security Metamodel Service"""
    
    def __init__(self) -> None:
        self.entities: Dict[str, EntityDefinition] = {}
        self.relations: Dict[str, SemanticRelation] = {}
        self.ontology_classes: Dict[str, OntologyClass] = {}
        self.mappings: Dict[str, KnowledgeMapping] = {}
        self._init_default_ontology()
    
    def _init_default_ontology(self) -> None:
        """Initialize default ontology classes"""
        classes = [
            OntologyClass(
                class_id="threat",
                name="Threat",
                parent_class_id=None,
                properties=["name", "type", "severity", "ttp"],
                description="Any malicious activity in cyberspace"
            ),
            OntologyClass(
                class_id="actor",
                name="Threat Actor",
                parent_class_id=None,
                properties=["name", "type", "motivation", "capability"],
                description="Entity responsible for threat activity"
            ),
            OntologyClass(
                class_id="campaign",
                name="Campaign",
                parent_class_id=None,
                properties=["name", "objective", "start_date", "end_date"],
                description="Coordinated threat activity over time"
            ),
            OntologyClass(
                class_id="vulnerability",
                name="Vulnerability",
                parent_class_id=None,
                properties=["cve_id", "severity", "affected_systems"],
                description="Security weakness that can be exploited"
            ),
            OntologyClass(
                class_id="control",
                name="Security Control",
                parent_class_id=None,
                properties=["name", "type", "category", "effectiveness"],
                description="Measure to mitigate risk"
            )
        ]
        for cls in classes:
            self.ontology_classes[cls.class_id] = cls
    
    def register_entity(
        self,
        name: str,
        category: str,
        description: str,
        properties: Optional[Dict[str, Any]] = None,
        schema: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Register a universal entity"""
        entity = EntityDefinition(
            entity_id=str(uuid4())[:8],
            name=name,
            category=EntityCategory(category),
            description=description,
            properties=properties or {},
            schema=schema or {}
        )
        self.entities[entity.entity_id] = entity
        return entity.to_dict()
    
    def get_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get an entity"""
        entity = self.entities.get(entity_id)
        return entity.to_dict() if entity else None
    
    def get_all_entities(self) -> List[Dict[str, Any]]:
        """Get all entities"""
        return [e.to_dict() for e in self.entities.values()]
    
    def get_entities_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get entities by category"""
        return [e.to_dict() for e in self.entities.values() 
                if e.category == EntityCategory(category)]
    
    def create_relation(
        self,
        source_entity_id: str,
        target_entity_id: str,
        relationship_type: str,
        metadata: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0
    ) -> Dict[str, Any]:
        """Create a semantic relation"""
        relation = SemanticRelation(
            relation_id=str(uuid4())[:8],
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            relationship_type=RelationshipType(relationship_type),
            metadata=metadata or {},
            confidence=confidence
        )
        self.relations[relation.relation_id] = relation
        return relation.to_dict()
    
    def get_relation(self, relation_id: str) -> Optional[Dict[str, Any]]:
        """Get a relation"""
        relation = self.relations.get(relation_id)
        return relation.to_dict() if relation else None
    
    def get_entity_relations(self, entity_id: str) -> List[Dict[str, Any]]:
        """Get all relations for an entity"""
        return [r.to_dict() for r in self.relations.values()
                if r.source_entity_id == entity_id or r.target_entity_id == entity_id]
    
    def get_ontology_classes(self) -> List[Dict[str, Any]]:
        """Get all ontology classes"""
        return [c.to_dict() for c in self.ontology_classes.values()]
    
    def create_mapping(
        self,
        source_concept: str,
        target_concept: str,
        mapping_type: str,
        bidirectional: bool = False
    ) -> Dict[str, Any]:
        """Create a knowledge mapping"""
        mapping = KnowledgeMapping(
            mapping_id=str(uuid4())[:8],
            source_concept=source_concept,
            target_concept=target_concept,
            mapping_type=mapping_type,
            bidirectional=bidirectional
        )
        self.mappings[mapping.mapping_id] = mapping
        return mapping.to_dict()
    
    def get_mapping(self, mapping_id: str) -> Optional[Dict[str, Any]]:
        """Get a mapping"""
        mapping = self.mappings.get(mapping_id)
        return mapping.to_dict() if mapping else None
    
    def search_concepts(self, query: str) -> Dict[str, Any]:
        """Search across entities, classes, and mappings"""
        query_lower = query.lower()
        
        # Search entities
        entities = [e.to_dict() for e in self.entities.values()
                   if query_lower in e.name.lower() or query_lower in e.description.lower()]
        
        # Search ontology classes
        classes = [c.to_dict() for c in self.ontology_classes.values()
                  if query_lower in c.name.lower()]
        
        # Search mappings
        mappings = [m.to_dict() for m in self.mappings.values()
                   if query_lower in m.source_concept.lower() 
                   or query_lower in m.target_concept.lower()]
        
        return {
            "query": query,
            "entities": entities,
            "classes": classes,
            "mappings": mappings,
            "total_results": len(entities) + len(classes) + len(mappings)
        }
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get metamodel dashboard"""
        category_counts: Dict[str, int] = {}
        for entity in self.entities.values():
            category_counts[entity.category.value] = \
                category_counts.get(entity.category.value, 0) + 1
        
        return {
            "total_entities": len(self.entities),
            "total_relations": len(self.relations),
            "total_classes": len(self.ontology_classes),
            "total_mappings": len(self.mappings),
            "entities_by_category": category_counts
        }


# Global service instance
_metamodel_service: Optional[SecurityMetamodelService] = None

def get_metamodel_service() -> SecurityMetamodelService:
    """Get the global service instance"""
    global _metamodel_service
    if _metamodel_service is None:
        _metamodel_service = SecurityMetamodelService()
    return _metamodel_service