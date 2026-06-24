"""Security Metamodel Module
Enterprise Security Metamodel for AegisGraph.
Universal ontology and semantic framework for all entities.
"""
from .models import (
    EntityDefinition, SemanticRelation, OntologyClass, KnowledgeMapping,
    EntityCategory, RelationshipType
)
from .service import SecurityMetamodelService, get_metamodel_service

__all__ = [
    "EntityDefinition",
    "SemanticRelation",
    "OntologyClass",
    "KnowledgeMapping",
    "EntityCategory",
    "RelationshipType",
    "SecurityMetamodelService",
    "get_metamodel_service"
]