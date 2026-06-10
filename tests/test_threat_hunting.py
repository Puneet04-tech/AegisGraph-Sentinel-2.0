"""
Test Suite for Phase 34: AI Threat Hunting & Security Analytics Platform
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from src.api.main import app
from src.threat_hunting import get_threat_hunting_service, get_store
from src.threat_hunting.models import (
    HuntState,
    ThreatSeverity,
    IndicatorType,
    CampaignStatus,
    ThreatHunt,
    ThreatIndicator,
    BehaviorProfile,
    ThreatCampaign,
    AttackPath,
    ThreatCorrelation,
    ThreatScore,
    HuntResult,
)


@pytest.fixture(autouse=True)
def clean_store():
    """Ensure the threat hunting store is clean before each test."""
    store = get_store()
    store.reset()
    yield
    store.reset()


# --- Unit Tests ---

def test_threat_scoring():
    """Test Threat Scoring Engine logic and mapping to severity levels."""
    service = get_threat_hunting_service()
    
    # Low Threat Score
    score = service.scoring_engine.calculate_score("user_1", behavior_score=0.1)
    assert score.score < 0.25
    assert score.severity == ThreatSeverity.LOW

    # Critical Threat Score
    score = service.scoring_engine.calculate_score(
        "user_2",
        behavior_score=0.9,
        campaign_score=0.8,
        graph_score=0.7,
        intel_score=0.9,
    )
    assert score.score > 0.75
    assert score.severity == ThreatSeverity.CRITICAL


def test_behavior_analytics():
    """Test Behavior Analytics Engine updates and deviation checks."""
    service = get_threat_hunting_service()
    
    # Baseline setup
    service.behavior_engine.update_profile_statistics(
        entity_id="entity_1",
        amounts=[100.0, 110.0, 95.0, 105.0],
        hours=[9, 10, 11],
        ips=["192.168.1.50"],
        devices=["device_mac_1"],
    )
    
    # Typical behavior check
    result = service.behavior_engine.evaluate_behavior(
        entity_id="entity_1",
        amount=102.0,
        hour=10,
        ip="192.168.1.50",
        device_id="device_mac_1",
        recent_txn_count_1m=1,
    )
    assert result["overall_deviation"] < 0.05

    # Anomalous behavior check
    result = service.behavior_engine.evaluate_behavior(
        entity_id="entity_1",
        amount=500.0,  # Deviaion in amount
        hour=23,       # Deviation in hour
        ip="203.0.113.1", # Deviation in IP
        device_id="new_device", # Deviation in device
        recent_txn_count_1m=10, # Deviation in velocity
    )
    assert result["overall_deviation"] > 0.4
    assert result["breakdown"]["amount_deviation"] > 0.0
    assert result["breakdown"]["time_deviation"] > 0.0
    assert result["breakdown"]["network_deviation"] > 0.0


def test_anomaly_detection():
    """Test Anomaly Detector classifier mapping context data to indicators."""
    service = get_threat_hunting_service()
    
    indicators = service.anomaly_detector.detect_anomalies(
        entity_id="user_test",
        operation="delete_account",
        ip_address="200.5.5.5",
        device_status="STOLEN",
        failed_attempts=4,
    )
    
    assert len(indicators) == 4
    types = [ind.indicator_type for ind in indicators]
    assert IndicatorType.FINGERPRINT in types
    assert IndicatorType.VELOCITY in types
    assert IndicatorType.BEHAVIOR in types
    assert IndicatorType.IP in types


def test_pattern_detection():
    """Test Attack Pattern Detector parsing complex sequences."""
    service = get_threat_hunting_service()
    
    events = [
        {"event_type": "auth_failed", "device_id": "d1"},
        {"event_type": "auth_failed", "device_id": "d1"},
        {"event_type": "credential_update", "device_id": "d1"},
        {"event_type": "transaction", "amount": 2000.0, "device_id": "d1"},
    ]
    
    # Account Takeover detection
    indicators = service.pattern_detector.detect_patterns(
        user_id="user_ato",
        events=events,
        relationships=[],
    )
    assert len(indicators) == 1
    assert "Account Takeover" in indicators[0].description

    # Transfer Loop detection
    rels = [
        {"from_id": "A", "to_id": "B", "type": "transfer"},
        {"from_id": "B", "to_id": "C", "type": "transfer"},
        {"from_id": "C", "to_id": "A", "type": "transfer"},
    ]
    indicators_loop = service.pattern_detector.detect_patterns(
        user_id="A",
        events=[],
        relationships=rels,
    )
    assert len(indicators_loop) == 1
    assert "Circular Transfer" in indicators_loop[0].description


def test_graph_explorer_paths():
    """Test Graph Explorer path discovery and BFS/DFS routing."""
    service = get_threat_hunting_service()
    
    service.scoring_engine.calculate_score("Target", behavior_score=1.0, campaign_score=1.0, graph_score=1.0, intel_score=1.0)
    
    rels = [
        {"from_id": "Start", "to_id": "Hop1", "type": "device"},
        {"from_id": "Hop1", "to_id": "Target", "type": "transfer"},
    ]
    
    paths = service.discover_attack_paths(start_entity="Start", relationships=rels)
    assert len(paths) >= 1
    assert paths[0].nodes[0]["id"] == "Start"
    assert paths[0].nodes[-1]["id"] == "Target"


# --- Integration Tests ---

def test_threat_hunt_workflow():
    """Test full threat hunt creation, query execution, and result capture."""
    service = get_threat_hunting_service()
    
    # Pre-populate scores in database
    service.scoring_engine.calculate_score("user_threat_1", behavior_score=0.8)  # score ~ 0.28
    service.scoring_engine.calculate_score("user_threat_2", behavior_score=0.9, campaign_score=0.9)  # score ~ 0.54
    
    # Start hunt
    hunt = service.start_hunt(
        name="High Risk Hunt",
        description="Find all entities with threat score >= 0.2",
        query_criteria={"min_threat_score": 0.2},
    )
    
    assert hunt.state == HuntState.COMPLETED
    assert hunt.findings_count >= 2
    
    results = service.store.get_results_for_hunt(hunt.hunt_id)
    assert len(results) >= 2


def test_threat_correlation():
    """Test correlation engine group scaling."""
    service = get_threat_hunting_service()
    
    ind1 = service.anomaly_detector.detect_anomalies("U1", "read", "1.1.1.1", "UNKNOWN", 5, {})[0]
    ind2 = service.anomaly_detector.detect_anomalies("U2", "read", "2.2.2.2", "STOLEN", 0, {})[0]
    
    correlation = service.correlate_threats(
        name="Linked Attack Correlation",
        entities=["U1", "U2"],
        indicator_ids=[ind1.indicator_id, ind2.indicator_id],
    )
    assert correlation.correlation_score > 0.3


# --- API Endpoint Routing Tests ---

def test_api_endpoints():
    """Test FastAPI endpoint routing and JSON schema bindings."""
    client = TestClient(app)
    
    # Setup test credentials header
    headers = {"X-API-Key": "SUPER_ADMIN"}

    # 1. POST /api/v1/threat-hunting/query
    query_payload = {
        "entity_id": "user_api_1",
        "entity_type": "user",
        "amount": 1500.0,
        "hour": 23,
        "ip_address": "203.0.113.100",  # Malicious IP
        "device_id": "d_api_1",
        "device_status": "BLOCKED",
        "failed_attempts": 4,
        "operation": "export_data",
        "recent_txn_count_1m": 8,
    }
    response = client.post("/api/v1/threat-hunting/query", json=query_payload, headers=headers)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["entity_id"] == "user_api_1"
    assert res_data["score"] > 0.3

    # 2. GET /api/v1/threat-hunting/anomalies
    response = client.get("/api/v1/threat-hunting/anomalies", headers=headers)
    assert response.status_code == 200
    assert len(response.json()) > 0

    # 3. POST /api/v1/threat-hunting/start
    start_payload = {
        "name": "API Triggered Hunt",
        "description": "Triggered via API testing client",
        "query_criteria": {"min_threat_score": 0.3},
    }
    response = client.post("/api/v1/threat-hunting/start", json=start_payload, headers=headers)
    assert response.status_code == 200
    hunt_data = response.json()
    assert hunt_data["name"] == "API Triggered Hunt"
    hunt_id = hunt_data["hunt_id"]

    # 4. GET /api/v1/threat-hunting/results/{id}
    response = client.get(f"/api/v1/threat-hunting/results/{hunt_id}", headers=headers)
    assert response.status_code == 200
    assert len(response.json()) > 0

    # 5. GET /api/v1/threat-hunting/campaigns
    response = client.get("/api/v1/threat-hunting/campaigns", headers=headers)
    assert response.status_code == 200

    # 6. GET /api/v1/threat-hunting/dashboard
    response = client.get("/api/v1/threat-hunting/dashboard", headers=headers)
    assert response.status_code == 200
    db_data = response.json()
    assert "store_stats" in db_data
