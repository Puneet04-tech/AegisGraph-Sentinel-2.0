import pytest
from fastapi.testclient import TestClient
from src.api.main import app
from src.case_management.store import get_case_store
from src.case_management.models import CasePriority
from src.threat_intelligence import (
    get_threat_store,
    extract_features_from_case,
    correlate_alert,
    detect_campaigns,
)

client = TestClient(app)

HEADERS = {
    "X-API-Key": "test_analyst_key",
    "X-Analyst-ID": "test_analyst_1",
}


@pytest.fixture(autouse=True)
def clean_stores():
    """Reset all in-memory stores before each test run."""
    case_store = get_case_store()
    threat_store = get_threat_store()
    
    case_store._cases.clear()
    case_store._comments.clear()
    case_store._evidence.clear()
    case_store._audit.clear()
    
    threat_store._indicators.clear()
    threat_store._actors.clear()
    threat_store._campaigns.clear()
    threat_store._correlations.clear()
    # Re-initialize default patterns
    threat_store._patterns.clear()
    threat_store._init_default_patterns()


def test_feature_extraction():
    """Verify that IP, Device ID, and Account ID are correctly parsed from cases or stable fallbacks."""
    case_store = get_case_store()
    case = case_store.create_case(
        transaction_id="TXN_STABLE123",
        risk_score=0.8,
        decision="REVIEW",
        analyst_id="analyst1",
        tags=["ip:10.20.30.40", "device:DEV_TESTING1"]
    )
    
    ip, device, account = extract_features_from_case(case)
    assert ip == "10.20.30.40"
    assert device == "DEV_TESTING1"
    assert account is not None  # Fallback generated account based on stable hash


def test_correlation_engine():
    """Verify that multiple cases sharing identical features are correlated."""
    case_store = get_case_store()
    
    # Create 3 cases sharing same IP (192.168.1.100) via tags
    c1 = case_store.create_case("TXN_1", 0.9, "BLOCK", "analyst1", tags=["ip:192.168.1.100", "device:DEV_A"])
    c2 = case_store.create_case("TXN_2", 0.85, "REVIEW", "analyst1", tags=["ip:192.168.1.100", "device:DEV_B"])
    c3 = case_store.create_case("TXN_3", 0.4, "ALLOW", "analyst1", tags=["ip:192.168.1.100", "device:DEV_C"])
    
    # Run correlation on c1 (should pick up c2 and c3 sharing IP)
    corr = correlate_alert(c1.case_id)
    assert corr is not None
    assert len(corr.case_ids) == 3
    assert c1.case_id in corr.case_ids
    assert c2.case_id in corr.case_ids
    assert c3.case_id in corr.case_ids
    assert "ip=192.168.1.100" in corr.common_features


def test_campaign_detection_and_actors():
    """Verify that correlations of size 3+ trigger Campaign creation and Threat Actor assignment."""
    case_store = get_case_store()
    
    # Create 3 high-risk cases sharing IP and device
    c1 = case_store.create_case("TXN_1", 0.9, "BLOCK", "analyst1", tags=["ip:172.16.0.5", "device:DEV_CAMPAIGN_1"])
    c2 = case_store.create_case("TXN_2", 0.85, "REVIEW", "analyst1", tags=["ip:172.16.0.5", "device:DEV_CAMPAIGN_1"])
    c3 = case_store.create_case("TXN_3", 0.92, "BLOCK", "analyst1", tags=["ip:172.16.0.5", "device:DEV_CAMPAIGN_1"])
    
    correlate_alert(c1.case_id)
    
    campaigns = detect_campaigns()
    assert len(campaigns) == 1
    campaign = campaigns[0]
    assert campaign.severity == "MEDIUM"  # 3 cases
    assert campaign.threat_actor_id is not None
    
    threat_store = get_threat_store()
    actor = threat_store.get_actor(campaign.threat_actor_id)
    assert actor is not None
    assert "172.16.0.5" in actor.associated_ips
    assert "DEV_CAMPAIGN_1" in actor.associated_devices


# --- API Endpoint Testing ---

def test_endpoints_initial_empty():
    """Verify that command center stats reflect empty stores correctly."""
    response = client.get("/api/v1/threat-intelligence/command-center/stats", headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["total_correlated_alerts"] == 0
    assert data["active_campaigns_count"] == 0
    assert data["total_threat_indicators"] == 0
    assert data["global_threat_level"] == 0.5


def test_manually_add_indicator():
    """Test manual addition of threat indicator."""
    payload = {
        "indicator_type": "IP",
        "value": "198.51.100.42",
        "source_feed": "MANUAL_TEST",
        "threat_score": 0.88,
        "confidence": 0.95
    }
    response = client.post("/api/v1/threat-intelligence/indicators", json=payload, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["indicator_type"] == "IP"
    assert data["value"] == "198.51.100.42"
    assert data["threat_score"] == 0.88
    assert "indicator_id" in data


def test_command_center_stats_with_data():
    """Create cases via API, which triggers threat engine, and check command center stats."""
    # Create case 1
    payload1 = {
        "transaction_id": "TXN_A",
        "risk_score": 0.95,
        "decision": "BLOCK",
        "priority": "HIGH",
        "tags": ["ip:192.0.2.1", "device:DEV_ALERT_X"]
    }
    response1 = client.post("/api/v1/cases", json=payload1, headers=HEADERS)
    assert response1.status_code == 200
    c1_id = response1.json()["case_id"]

    # Create case 2 (correlated via IP and Device ID)
    payload2 = {
        "transaction_id": "TXN_B",
        "risk_score": 0.85,
        "decision": "REVIEW",
        "priority": "MEDIUM",
        "tags": ["ip:192.0.2.1", "device:DEV_ALERT_X"]
    }
    response2 = client.post("/api/v1/cases", json=payload2, headers=HEADERS)
    assert response2.status_code == 200
    c2_id = response2.json()["case_id"]

    # Create case 3 (completes campaign cluster)
    payload3 = {
        "transaction_id": "TXN_C",
        "risk_score": 0.90,
        "decision": "BLOCK",
        "priority": "CRITICAL",
        "tags": ["ip:192.0.2.1", "device:DEV_ALERT_X"]
    }
    response3 = client.post("/api/v1/cases", json=payload3, headers=HEADERS)
    assert response3.status_code == 200

    # Fetch Command Center stats
    response = client.get("/api/v1/threat-intelligence/command-center/stats", headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    
    assert data["total_correlated_alerts"] == 3
    assert data["active_campaigns_count"] == 1
    # 3 indicators created: 1 IP (192.0.2.1) + 1 Device (DEV_ALERT_X) + 1 Account (stable hash fallback for transaction)
    # Actually, because c1, c2, c3 are high risk (>0.7), each generates indicators.
    # IP and device indicators are deduplicated in store, but fallback account indicators are distinct per transaction.
    # So we expect: 1 IP + 1 Device + 3 Accounts = 5 indicators.
    assert data["total_threat_indicators"] == 5
    assert data["global_threat_level"] > 0.7
