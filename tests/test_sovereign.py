"""Tests for Sovereign Federation Module"""
import pytest
from src.sovereign_federation import SovereignFederationService, FederationRole

def test_service_init():
    """Test service initialization"""
    service = SovereignFederationService()
    assert service is not None
    assert len(service.entities) >= 3

def test_register_entity():
    """Test registering an entity"""
    service = SovereignFederationService()
    entity = service.register_entity(
        name="Test CERT",
        country_code="US",
        entity_type="CERT",
        federation_role="PARTICIPANT",
        trust_score=0.7
    )
    assert entity is not None
    assert entity["name"] == "Test CERT"
    assert entity["country_code"] == "US"

def test_get_entity():
    """Test getting an entity"""
    service = SovereignFederationService()
    created = service.register_entity("Get Test", "EU", "AGENCY")
    retrieved = service.get_entity(created["entity_id"])
    assert retrieved is not None
    assert retrieved["name"] == "Get Test"

def test_get_all_entities():
    """Test getting all entities"""
    service = SovereignFederationService()
    entities = service.get_all_entities()
    assert len(entities) >= 3

def test_get_entities_by_country():
    """Test filtering by country"""
    service = SovereignFederationService()
    service.register_entity("US Entity", "US", "CERT")
    entities = service.get_entities_by_country("US")
    assert all(e["country_code"] == "US" for e in entities)

def test_create_policy():
    """Test creating a policy"""
    service = SovereignFederationService()
    policy = service.create_policy(
        name="US Data Sovereignty",
        description="US data handling rules",
        country_code="US",
        rules=[{"rule": "data_locality", "required": True}]
    )
    assert policy is not None
    assert policy["name"] == "US Data Sovereignty"

def test_share_intelligence():
    """Test sharing intelligence"""
    service = SovereignFederationService()
    share = service.share_intelligence(
        source_entity_id="entity-us-cert",
        target_entity_id="entity-eu-enisa",
        content_summary="Threat intel about APT29",
        data_classification="CONFIDENTIAL"
    )
    assert share is not None
    assert share["status"] == "APPROVED"

def test_verify_compliance():
    """Test compliance verification"""
    service = SovereignFederationService()
    entity = service.register_entity("Compliance Test", "US", "CERT")
    policy = service.create_policy("Test Policy", "Desc", "US", [])
    
    record = service.verify_compliance(entity["entity_id"], policy["policy_id"])
    assert record is not None
    assert record["status"] == "VERIFIED"

def test_get_compliance_records():
    """Test getting compliance records"""
    service = SovereignFederationService()
    entity = service.register_entity("Records Test", "EU", "AGENCY")
    policy = service.create_policy("Records Policy", "Desc", "EU", [])
    service.verify_compliance(entity["entity_id"], policy["policy_id"])
    
    records = service.get_compliance_records(entity["entity_id"])
    assert len(records) >= 1

def test_get_dashboard():
    """Test dashboard data"""
    service = SovereignFederationService()
    dashboard = service.get_dashboard()
    assert dashboard is not None
    assert "total_entities" in dashboard
    assert "entities_by_role" in dashboard