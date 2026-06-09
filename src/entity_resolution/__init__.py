"""
Entity Resolution Module for AegisGraph Sentinel 2.0

Production-grade Entity Resolution and Knowledge Graph Engine capable of:
- Linking related fraud entities
- Detecting fraud rings
- Propagating risk across connected entities
- Exposing hidden relationships between investigations

Exports:
    Entity: Core entity data model
    EntityRelationship: Relationship between entities
    FraudCluster: Fraud ring cluster model
    EntityStore: Thread-safe entity storage with LRU cache
    EntityResolver: Entity resolution engine
    KnowledgeGraph: Graph-based entity relationship storage
    ClusterEngine: Fraud ring detection engine
    RiskPropagator: Risk propagation engine
"""

from .models import Entity, EntityRelationship, FraudCluster
from .store import EntityStore, get_entity_store
from .entity_resolver import EntityResolver, get_entity_resolver
from .knowledge_graph import KnowledgeGraph, get_knowledge_graph
from .cluster_engine import ClusterEngine, get_cluster_engine
from .risk_propagation import RiskPropagator, get_risk_propagator

__all__ = [
    "Entity",
    "EntityRelationship",
    "FraudCluster",
    "EntityStore",
    "get_entity_store",
    "EntityResolver",
    "get_entity_resolver",
    "KnowledgeGraph",
    "get_knowledge_graph",
    "ClusterEngine",
    "get_cluster_engine",
    "RiskPropagator",
    "get_risk_propagator",
]