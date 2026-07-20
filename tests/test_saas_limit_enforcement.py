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

def test_placeholder_user_api_is_not_mounted() -> None:
    client = TestClient(app)

    response = client.post(
        "/api/v1/users/",
        params={"tenant_id": "tenant_test"},
        json={
            "email": "user@example.com",
            "full_name": "User",
            "username": "user",
            "password": "password123",
            "role": "admin",
        },
    )

    assert response.status_code == 404
