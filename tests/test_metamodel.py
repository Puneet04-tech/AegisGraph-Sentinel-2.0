"""Tests for Security Metamodel Module"""
import pytest
from src.security_metamodel import SecurityMetamodelService, EntityCategory

def test_service_init():
    """Test service initialization"""
    service = SecurityMetamodelService()
    assert service is not None
    assert len(service.ontology_classes) >= 5

def test_register_entity():
    """Test registering an entity"""
    service = SecurityMetamodelService()
    entity = service.register_entity(
        name="APT29",
        category="THREAT",
        description="Cozy Bear threat group",
        properties={"country": "RU", "aliases": ["Cozy Bear"]}
    )
    assert entity is not None
    assert entity["name"] == "APT29"
    assert entity["category"] == "THREAT"

def test_get_entity():
    """Test getting an entity"""
    service = SecurityMetamodelService()
    created = service.register_entity("Test Entity", "ASSET", "Test description")
    retrieved = service.get_entity(created["entity_id"])
    assert retrieved is not None
    assert retrieved["name"] == "Test Entity"

def test_get_all_entities():
    """Test getting all entities"""
    service = SecurityMetamodelService()
    service.register_entity("Entity 1", "THREAT", "Desc")
    service.register_entity("Entity 2", "ASSET", "Desc")
    entities = service.get_all_entities()
    assert len(entities) >= 2

def test_get_entities_by_category():
    """Test filtering by category"""
    service = SecurityMetamodelService()
    service.register_entity("Threat 1", "THREAT", "Desc")
    service.register_entity("Threat 2", "THREAT", "Desc")
    service.register_entity("Asset 1", "ASSET", "Desc")
    threats = service.get_entities_by_category("THREAT")
    assert all(e["category"] == "THREAT" for e in threats)

def test_create_relation():
    """Test creating a relation"""
    service = SecurityMetamodelService()
    entity1 = service.register_entity("Attacker", "ACTOR", "Threat actor")
    entity2 = service.register_entity("Target", "ASSET", "Target asset")
    relation = service.create_relation(
        source_entity_id=entity1["entity_id"],
        target_entity_id=entity2["entity_id"],
        relationship_type="TARGETS"
    )
    assert relation is not None
    assert relation["relationship_type"] == "TARGETS"

def test_get_entity_relations():
    """Test getting entity relations"""
    service = SecurityMetamodelService()
    entity1 = service.register_entity("Entity A", "THREAT", "Desc")
    entity2 = service.register_entity("Entity B", "VULNERABILITY", "Desc")
    service.create_relation(entity1["entity_id"], entity2["entity_id"], "EXPLOITS")
    relations = service.get_entity_relations(entity1["entity_id"])
    assert len(relations) >= 1

def test_get_ontology_classes():
    """Test getting ontology classes"""
    service = SecurityMetamodelService()
    classes = service.get_ontology_classes()
    assert len(classes) >= 5
    class_names = [c["name"] for c in classes]
    assert "Threat" in class_names
    assert "Campaign" in class_names

def test_create_mapping():
    """Test creating a mapping"""
    service = SecurityMetamodelService()
    mapping = service.create_mapping(
        source_concept="Fraud",
        target_concept="Financial Crime",
        mapping_type="SYNONYM",
        bidirectional=True
    )
    assert mapping is not None
    assert mapping["source_concept"] == "Fraud"

def test_search_concepts():
    """Test searching concepts"""
    service = SecurityMetamodelService()
    service.register_entity("APT41", "THREAT", "Chinese threat actor")
    service.register_entity("APT29", "THREAT", "Russian threat actor")
    results = service.search_concepts("APT")
    assert results is not None
    assert results["total_results"] >= 2

def test_get_dashboard():
    """Test dashboard data"""
    service = SecurityMetamodelService()
    service.register_entity("Test Entity", "CONTROL", "Test")
    dashboard = service.get_dashboard()
    assert dashboard is not None
    assert "total_entities" in dashboard
    assert "total_classes" in dashboard
    assert "entities_by_category" in dashboard