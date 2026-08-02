import pytest
from fastapi import HTTPException
from src.saas.services.limit_enforcer import enforce_tenant_limit, set_tenant_resource_count
from src.saas.services.billing import PriceTier
from fastapi.testclient import TestClient
from src.api.main import app

from src.saas.services.billing import billing_service, UsageMeteringService

def test_enforce_tenant_limit_within() -> None:
    # Set current count to 3, which is within the COMMUNITY limit of 5
    set_tenant_resource_count("org_1", "max_users", 3)
    # This should not raise any exception
    enforce_tenant_limit("org_1", "max_users", PriceTier.COMMUNITY)

def test_enforce_tenant_limit_at_quota() -> None:
    # Set current count to 5, which is exactly the COMMUNITY limit of 5
    set_tenant_resource_count("org_quota_exact", "max_users", 5)
    # A tenant exactly at their allowed quota should be allowed (no exception)
    enforce_tenant_limit("org_quota_exact", "max_users", PriceTier.COMMUNITY)

def test_enforce_tenant_limit_exceeded() -> None:
    # Set current count to 6, which exceeds the COMMUNITY limit of 5
    set_tenant_resource_count("org_2", "max_users", 6)
    
    # This should raise HTTPException with status 402
    with pytest.raises(HTTPException) as excinfo:
        enforce_tenant_limit("org_2", "max_users", PriceTier.COMMUNITY)
    
    assert excinfo.value.status_code == 402
    assert "limit exceeded" in excinfo.value.detail.lower()

def test_usage_metering_quota_boundary_fields() -> None:
    metering = UsageMeteringService(billing_service)
    
    # 1. Below limit (usage = 4, limit = 5)
    res_below = metering.check_limit("org_t", "max_users", 4, PriceTier.COMMUNITY)
    assert res_below["within_limit"] is True
    assert res_below["over_limit"] is False
    assert res_below["remaining"] == 1
    assert res_below["percentage"] == 80.0
    assert res_below["approaching_limit"] is True

    # 2. Exactly at limit (usage = 5, limit = 5)
    res_exact = metering.check_limit("org_t", "max_users", 5, PriceTier.COMMUNITY)
    assert res_exact["within_limit"] is True
    assert res_exact["over_limit"] is False
    assert res_exact["remaining"] == 0
    assert res_exact["percentage"] == 100.0
    assert res_exact["approaching_limit"] is True

    # 3. Above limit (usage = 6, limit = 5)
    res_above = metering.check_limit("org_t", "max_users", 6, PriceTier.COMMUNITY)
    assert res_above["within_limit"] is False
    assert res_above["over_limit"] is True
    assert res_above["remaining"] == 0
    assert res_above["percentage"] == 120.0
    assert res_above["approaching_limit"] is True


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
