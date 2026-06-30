"""
Security tests for health and monitoring endpoints.

Tests verify that:
1. Unauthenticated access is properly blocked
2. Role-based access controls are enforced
3. Verbose health checks require ADMIN role
4. Sensitive information is protected
5. Rate limiting works on liveness probe
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import hashlib
import os


class TestHealthEndpointSecurity:
    """Test suite for health endpoint security controls."""

    def test_root_endpoint_requires_authentication(self, client: TestClient):
        """Root endpoint should require VIEWER role or higher."""
        # Test without authentication
        response = client.get("/")
        assert response.status_code in [401, 403], \
            f"Root endpoint should require auth, got {response.status_code}"

    def test_root_endpoint_with_viewer_role(self, client: TestClient, viewer_api_key: str):
        """Root endpoint should be accessible with VIEWER role."""
        response = client.get("/", headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "version" in data

    def test_liveness_probe_rate_limited(self, client: TestClient):
        """Liveness probe should have rate limiting."""
        # Make multiple requests to test rate limiting
        for i in range(105):  # Exceed the 100 request limit
            response = client.get("/health/liveness")
            if i < 100:
                assert response.status_code == 200
            else:
                # Should be rate limited after 100 requests
                assert response.status_code == 429

    def test_liveness_probe_returns_basic_info(self, client: TestClient):
        """Liveness probe should return minimal information."""
        response = client.get("/health/liveness")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "service" in data
        # Should not expose detailed information
        assert "uptime_seconds" not in data
        assert "model_loaded" not in data

    def test_health_endpoint_requires_auth(self, client: TestClient):
        """Health endpoint should require authentication."""
        response = client.get("/health")
        assert response.status_code in [401, 403]

    def test_health_endpoint_non_verbose_with_viewer(self, client: TestClient, viewer_api_key: str):
        """Non-verbose health check should work with VIEWER role."""
        response = client.get("/health", headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "service" in data
        # Should not include verbose details
        assert "services_health" not in data
        assert "model_loaded" not in data

    def test_health_endpoint_verbose_requires_admin(self, client: TestClient, viewer_api_key: str):
        """Verbose health check should require ADMIN role."""
        response = client.get("/health?verbose=true", headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 403

    def test_health_endpoint_verbose_with_admin(self, client: TestClient, admin_api_key: str):
        """Verbose health check should work with ADMIN role."""
        response = client.get("/health?verbose=true", headers={"X-API-Key": admin_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        # Verbose mode should include detailed information
        assert "services_health" in data or "model_loaded" in data

    def test_health_endpoint_v1_requires_auth(self, client: TestClient):
        """Health v1 endpoint should require authentication."""
        response = client.get("/api/v1/health")
        assert response.status_code in [401, 403]

    def test_health_endpoint_v1_verbose_requires_admin(self, client: TestClient, viewer_api_key: str):
        """Health v1 verbose check should require ADMIN role."""
        response = client.get("/api/v1/health?verbose=true", headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 403


class TestMonitoringEndpointSecurity:
    """Test suite for monitoring endpoint security controls."""

    def test_stats_endpoint_requires_auditor(self, client: TestClient, viewer_api_key: str):
        """Stats endpoint should require AUDITOR role or higher."""
        response = client.get("/stats", headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 403

    def test_stats_endpoint_with_auditor(self, client: TestClient, auditor_api_key: str):
        """Stats endpoint should work with AUDITOR role."""
        response = client.get("/stats", headers={"X-API-Key": auditor_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "total_requests" in data
        assert "decisions" in data

    def test_model_info_requires_viewer(self, client: TestClient):
        """Model info endpoint should require VIEWER role."""
        response = client.get("/api/v1/model/info")
        assert response.status_code in [401, 403]

    def test_model_info_with_viewer(self, client: TestClient, viewer_api_key: str):
        """Model info endpoint should work with VIEWER role."""
        response = client.get("/api/v1/model/info", headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "model_name" in data
        assert "version" in data

    def test_memory_diagnostics_requires_admin(self, client: TestClient, viewer_api_key: str):
        """Memory diagnostics should require ADMIN role."""
        response = client.get("/api/v1/monitoring/memory", headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 403

    def test_memory_diagnostics_with_admin(self, client: TestClient, admin_api_key: str):
        """Memory diagnostics should work with ADMIN role."""
        response = client.get("/api/v1/monitoring/memory", headers={"X-API-Key": admin_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "memory" in data
        assert "caches" in data
        # Should not expose exact maxsize values
        assert "centrality_baseline_maxsize" not in data.get("caches", {})
        assert "centrality_baseline_has_maxsize" in data.get("caches", {})


class TestStatisticsEndpointSecurity:
    """Test suite for statistics endpoint security controls."""

    @pytest.mark.parametrize("endpoint", [
        "/api/v1/honeypot/stats",
        "/api/v1/entity-resolution/stats",
        "/api/v1/soc/stats",
        "/api/v1/governance/stats",
        "/api/v1/predictive/stats",
    ])
    def test_stats_endpoints_require_auditor(self, client: TestClient, viewer_api_key: str, endpoint: str):
        """Statistics endpoints should require AUDITOR role."""
        response = client.get(endpoint, headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 403, \
            f"Endpoint {endpoint} should require AUDITOR role"

    @pytest.mark.parametrize("endpoint", [
        "/api/v1/honeypot/stats",
        "/api/v1/entity-resolution/stats",
        "/api/v1/soc/stats",
        "/api/v1/governance/stats",
        "/api/v1/predictive/stats",
    ])
    def test_stats_endpoints_with_auditor(self, client: TestClient, auditor_api_key: str, endpoint: str):
        """Statistics endpoints should work with AUDITOR role."""
        # Note: Some endpoints may return 404 if modules are not loaded
        response = client.get(endpoint, headers={"X-API-Key": auditor_api_key})
        assert response.status_code in [200, 404], \
            f"Endpoint {endpoint} should be accessible with AUDITOR role (200 or 404 if module not loaded)"


class TestDataExposure:
    """Test suite for data exposure and sanitization."""

    def test_non_verbose_health_exposes_minimal_data(self, client: TestClient, viewer_api_key: str):
        """Non-verbose health check should expose minimal data."""
        response = client.get("/health", headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 200
        data = response.json()
        
        # Should expose basic information
        assert "status" in data
        assert "service" in data
        assert "version" in data
        assert "uptime_seconds" in data
        
        # Should NOT expose sensitive information
        assert "services_health" not in data
        assert "model_loaded" not in data
        assert "graph_loaded" not in data
        assert "innovations_available" not in data
        assert "requests_processed" not in data

    def test_verbose_health_exposes_detailed_data_to_admin(self, client: TestClient, admin_api_key: str):
        """Verbose health check can expose detailed data to ADMIN."""
        response = client.get("/health?verbose=true", headers={"X-API-Key": admin_api_key})
        assert response.status_code == 200
        data = response.json()
        
        # Should expose detailed information
        assert "status" in data
        assert "service" in data
        # May include services_health if health_monitor is available
        # May include model_loaded, graph_loaded, etc.

    def test_memory_diagnostics_sanitizes_maxsize(self, client: TestClient, admin_api_key: str):
        """Memory diagnostics should sanitize cache maxsize values."""
        response = client.get("/api/v1/monitoring/memory", headers={"X-API-Key": admin_api_key})
        assert response.status_code == 200
        data = response.json()
        
        caches = data.get("caches", {})
        # Should have the flag but not the actual value
        assert "centrality_baseline_has_maxsize" in caches
        assert "centrality_baseline_maxsize" not in caches


class TestRoleInheritance:
    """Test suite for role inheritance in access controls."""

    def test_admin_can_access_viewer_endpoints(self, client: TestClient, admin_api_key: str):
        """ADMIN role should inherit VIEWER permissions."""
        response = client.get("/", headers={"X-API-Key": admin_api_key})
        assert response.status_code == 200

    def test_admin_can_access_auditor_endpoints(self, client: TestClient, admin_api_key: str):
        """ADMIN role should inherit AUDITOR permissions."""
        response = client.get("/stats", headers={"X-API-Key": admin_api_key})
        assert response.status_code == 200

    def test_auditor_can_access_viewer_endpoints(self, client: TestClient, auditor_api_key: str):
        """AUDITOR role should inherit VIEWER permissions."""
        response = client.get("/", headers={"X-API-Key": auditor_api_key})
        assert response.status_code == 200

    def test_viewer_cannot_access_auditor_endpoints(self, client: TestClient, viewer_api_key: str):
        """VIEWER role should not access AUDITOR endpoints."""
        response = client.get("/stats", headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 403

    def test_viewer_cannot_access_admin_endpoints(self, client: TestClient, viewer_api_key: str):
        """VIEWER role should not access ADMIN endpoints."""
        response = client.get("/api/v1/monitoring/memory", headers={"X-API-Key": viewer_api_key})
        assert response.status_code == 403


# Fixtures for test setup
@pytest.fixture
def client():
    """Create a test client."""
    from src.api.main import app
    return TestClient(app)


@pytest.fixture
def viewer_api_key():
    """Provide a VIEWER role API key for testing."""
    # In a real setup, this would be configured via environment variables
    # For testing, we'll use a hash that matches the test configuration
    return os.getenv("TEST_VIEWER_API_KEY", "test_viewer_key")


@pytest.fixture
def auditor_api_key():
    """Provide an AUDITOR role API key for testing."""
    return os.getenv("TEST_AUDITOR_API_KEY", "test_auditor_key")


@pytest.fixture
def admin_api_key():
    """Provide an ADMIN role API key for testing."""
    return os.getenv("TEST_ADMIN_API_KEY", "test_admin_key")
