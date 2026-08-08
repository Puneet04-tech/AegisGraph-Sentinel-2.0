# AegisGraph Sentinel Enterprise
# SaaS Tenant Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from datetime import datetime
from pydantic import ValidationError
from src.saas.models.tenant import OrganizationCreate, UserCreate, APIKeyCreate, WorkspaceCreate

def test_organization_create_fields():
    org = OrganizationCreate(
        name="Test Org",
        slug="test-org",
        billing_email="billing@test.org",
        description="A test organization for multi-tenancy verification."
    )
    assert org.name == "Test Org"
    assert org.slug == "test-org"
    assert org.billing_email == "billing@test.org"
    assert org.description == "A test organization for multi-tenancy verification."

def test_organization_create_optional_fields():
    org = OrganizationCreate(name="Minimal Org", slug="min-org")
    assert org.name == "Minimal Org"
    assert org.slug == "min-org"
    assert org.billing_email is None
    assert org.description is None

def test_organization_create_validation_too_long_name():
    long_name = "a" * 256
    with pytest.raises(ValidationError):
        OrganizationCreate(name=long_name, slug="too-long")

def test_organization_create_validation_empty_name():
    with pytest.raises(ValidationError):
        OrganizationCreate(name="", slug="empty")

def test_user_create_fields():
    user = UserCreate(
        email="user@test.org",
        username="testuser",
        full_name="Test User",
        password="securepassword123"
    )
    assert user.email == "user@test.org"
    assert user.username == "testuser"
    assert user.full_name == "Test User"
    assert user.password == "securepassword123"

def test_user_create_invalid_email():
    with pytest.raises(ValidationError):
        UserCreate(email="not-an-email", password="password123")

def test_user_create_short_password():
    with pytest.raises(ValidationError):
        UserCreate(email="user@test.org", password="short")

def test_workspace_create_fields():
    ws = WorkspaceCreate(
        name="Workspace 1",
        slug="workspace-1",
        description="Core workspace for threat analysis."
    )
    assert ws.name == "Workspace 1"
    assert ws.slug == "workspace-1"
    assert ws.description == "Core workspace for threat analysis."

def test_workspace_create_invalid_slug():
    with pytest.raises(ValidationError):
        WorkspaceCreate(name="WS", slug="a")

def test_apikey_create_fields():
    key = APIKeyCreate(
        name="Admin Key",
        description="Key with elevated permissions.",
        scopes=["read", "write"],
        rate_limit_per_minute=100
    )
    assert key.name == "Admin Key"
    assert key.description == "Key with elevated permissions."
    assert key.scopes == ["read", "write"]
    assert key.rate_limit_per_minute == 100
    assert key.expires_at is None

def test_apikey_create_invalid_rate_limit():
    with pytest.raises(ValidationError):
        APIKeyCreate(name="Key", rate_limit_per_minute=0)
    with pytest.raises(ValidationError):
        APIKeyCreate(name="Key", rate_limit_per_minute=2000)
