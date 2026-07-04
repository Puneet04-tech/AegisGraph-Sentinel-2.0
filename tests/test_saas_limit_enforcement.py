import pytest
from fastapi import HTTPException
from src.saas.services.limit_enforcer import enforce_tenant_limit, set_tenant_resource_count
from src.saas.services.billing import PriceTier
from fastapi.testclient import TestClient
from src.api.main import app

def test_enforce_tenant_limit_within() -> None:
    # Set current count to 3, which is within the COMMUNITY limit of 5
    set_tenant_resource_count("org_1", "max_users", 3)
    # This should not raise any exception
    enforce_tenant_limit("org_1", "max_users", PriceTier.COMMUNITY)

def test_enforce_tenant_limit_exceeded() -> None:
    # Set current count to 5, which is exactly the COMMUNITY limit
    set_tenant_resource_count("org_2", "max_users", 5)
    
    # This should raise HTTPException with status 402
    with pytest.raises(HTTPException) as excinfo:
        enforce_tenant_limit("org_2", "max_users", PriceTier.COMMUNITY)
    
    assert excinfo.value.status_code == 402
    assert "limit exceeded" in excinfo.value.detail.lower()

def test_api_user_creation_limits() -> None:
    client = TestClient(app)
    
    # Reset limit count for tenant_test
    set_tenant_resource_count("tenant_test", "max_users", 0)
    
    # Create 5 users successfully (limit is 5)
    for i in range(5):
        resp = client.post(
            "/api/v1/users/?tenant_id=tenant_test",
            json={
                "email": f"user_{i}@example.com",
                "full_name": f"User {i}",
                "username": f"user_{i}",
                "password": "password123"
            }
        )
        assert resp.status_code == 201
    
    # The 6th user creation should be rejected with 402 (Payment Required)
    resp = client.post(
        "/api/v1/users/?tenant_id=tenant_test",
        json={
            "email": "user_overflow@example.com",
            "full_name": "Overflow User",
            "username": "overflow",
            "password": "password123"
        }
    )
    assert resp.status_code == 402
    json_data = resp.json()
    error_msg = json_data.get("detail") or json_data.get("error", {}).get("message", "")
    assert "limit exceeded" in error_msg.lower()
