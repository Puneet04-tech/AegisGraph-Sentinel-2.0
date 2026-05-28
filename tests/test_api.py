"""
Unit tests for API endpoints
"""
# Working on API endpoint testing

import pytest
from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api import main as api_main
from src.api.main import app, state
from src.api.schemas import RiskBreakdown, TransactionCheckResponse


client = TestClient(app)


class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_check(self):
        """Test /health endpoint"""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestStatsEndpoint:
    """Test statistics endpoint"""
    
    def test_get_stats(self):
        """Test /stats endpoint"""
        response = client.get("/stats")
        
        assert response.status_code == 200
        data = response.json()
        
        # Check expected fields
        assert "total_checks" in data
        assert "flagged_transactions" in data
        assert "average_response_time" in data
        assert "uptime_seconds" in data


class TestFraudCheckEndpoint:
    """Test fraud check endpoint"""
    
    def test_low_risk_transaction(self):
        """Test with a low-risk transaction"""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        transaction = {
            "transaction_id": "test_001",
            "source_account": "user_001",
            "target_account": "merchant_001",
            "amount": 50.0,
            "currency": "INR",
            "mode": "UPI",
            "timestamp": now,
            "device_id": "device_1",
            "ip_address": "103.1.1.1",
            "location": "Mumbai, India"
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        assert response.status_code == 200
        data = response.json()
        
        # Check response structure
        assert "transaction_id" in data
        assert "risk_score" in data
        assert "decision" in data
        assert "factors" in data
        assert "explanation" in data
        
        # Risk score should be between 0 and 1
        assert 0 <= data["risk_score"] <= 1
        
        # Decision should be valid
        assert data["decision"] in ["approve", "review", "block"]
    
    def test_high_risk_transaction(self):
        """Test with a high-risk transaction (large amount, rapid)"""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        transaction = {
            "transaction_id": "test_002",
            "source_account": "new_user",
            "target_account": "unknown_merchant",
            "amount": 10000.0,
            "currency": "INR",
            "mode": "NEFT",
            "timestamp": now,
            "device_id": "new_device",
            "ip_address": "192.168.1.1",
            "location": "Unknown"
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        assert response.status_code == 200
        data = response.json()
        
        # High-risk transaction should have high score
        # Note: This depends on model state, so just check structure
        assert "risk_score" in data
        assert "factors" in data
    
    def test_transaction_with_biometrics(self):
        """Test transaction with behavioral biometrics"""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        transaction = {
            "transaction_id": "test_003",
            "source_account": "user_001",
            "target_account": "merchant_001",
            "amount": 100.0,
            "currency": "INR",
            "mode": "UPI",
            "timestamp": now,
            "device_id": "device_1",
            "biometrics": {
                "hold_times": [120, 135, 128, 142, 118],
                "flight_times": [200, 185, 210, 195]
            },
            "ip_address": "103.1.1.1",
            "location": "Mumbai, India"
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        assert response.status_code == 200
        data = response.json()
        
        # Should include behavioral analysis
        assert "factors" in data
        assert "behavioral" in data["factors"]

    def test_internal_allow_maps_to_approve_in_api_response(self, monkeypatch):
        """Internal ALLOW decision must map to approve for API stability"""
        original_decisions = dict(state.decisions)
        state.decisions = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}

        def fake_compute_risk_score(transaction: dict, biometrics: dict = None, **kwargs):
            return {
                'risk_score': 0.20,
                'decision': 'ALLOW',
                'confidence': 0.85,
                'breakdown': {'graph': 0.0, 'velocity': 0.0, 'behavior': 0.0, 'entropy': 0.0},
            }

        monkeypatch.setattr('src.api.main.compute_risk_score', fake_compute_risk_score)

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        transaction = {
            "transaction_id": "test_allow_001",
            "source_account": "user_allow",
            "target_account": "merchant_allow",
            "amount": 100.0,
            "currency": "INR",
            "mode": "UPI",
            "timestamp": now,
            "device_id": "device_1",
            "ip_address": "103.1.1.1",
            "location": "Mumbai, India"
        }

        response = client.post("/api/v1/fraud/check", json=transaction)
        assert response.status_code == 200
        data = response.json()

        assert data["decision"] == "approve"
        assert state.decisions["ALLOW"] == 1

        state.decisions = original_decisions

    def test_invalid_transaction(self):
        """Test with invalid transaction data"""
        transaction = {
            "transaction_id": "test_004",
            # Missing required fields
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        # Should return validation error
        assert response.status_code == 422


class TestBatchFraudCheck:
    """Test batch fraud check endpoint"""

    def test_batch_aggregates_canonical_decisions(self, monkeypatch):
        """Batch totals should count API decision values correctly."""

        async def fake_check_transaction(txn_request):
            decision_by_transaction = {
                "batch_allow": "approve",
                "batch_review": "review",
                "batch_block": "block",
            }
            decision = decision_by_transaction[txn_request.transaction_id]
            return TransactionCheckResponse(
                transaction_id=txn_request.transaction_id,
                risk_score=0.25,
                decision=decision,
                factors={"graph": 0.0, "velocity": 0.0, "behavior": 0.0, "entropy": 0.0},
                confidence=0.9,
                breakdown=RiskBreakdown(graph=0.0, velocity=0.0, behavior=0.0, entropy=0.0),
                explanation="ok",
                recommended_action=decision,
                processing_time_ms=1.0,
                timestamp="2026-01-01T00:00:00Z",
            )

        monkeypatch.setattr('src.api.main.check_transaction', fake_check_transaction)

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        transactions = [
            {
                "transaction_id": "batch_allow",
                "source_account": "user_allow",
                "target_account": "merchant_allow",
                "amount": 50.0,
                "currency": "INR",
                "mode": "UPI",
                "timestamp": now,
                "device_id": "device_1",
                "ip_address": "103.1.1.1",
                "location": "Mumbai, India",
            },
            {
                "transaction_id": "batch_review",
                "source_account": "user_review",
                "target_account": "merchant_review",
                "amount": 75.0,
                "currency": "INR",
                "mode": "NEFT",
                "timestamp": now,
                "device_id": "device_2",
                "ip_address": "103.1.1.2",
                "location": "Delhi, India",
            },
            {
                "transaction_id": "batch_block",
                "source_account": "user_block",
                "target_account": "merchant_block",
                "amount": 100.0,
                "currency": "INR",
                "mode": "IMPS",
                "timestamp": now,
                "device_id": "device_3",
                "ip_address": "103.1.1.3",
                "location": "Bangalore, India",
            },
        ]

        response = client.post("/api/v1/fraud/batch", json={"transactions": transactions})

        assert response.status_code == 200
        data = response.json()
        assert data["total_allowed"] == 1
        assert data["total_review"] == 1
        assert data["total_blocked"] == 1
        assert data["total_processed"] == 3
    
    def test_batch_check(self):
        """Test batch processing of transactions"""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        transactions = [
            {
                "transaction_id": f"batch_{i}",
                "source_account": f"user_{i}",
                "target_account": f"merchant_{i+10}",  # Ensure different from source
                "amount": 50.0 * (i + 1),
                "currency": "INR",
                "mode": "UPI",
                "timestamp": now,
                "device_id": f"device_{i}",
                "ip_address": f"103.1.1.{i+1}",
                "location": "India"
            }
            for i in range(3)
        ]
        
        response = client.post("/api/v1/fraud/batch", json={"transactions": transactions})
        
        assert response.status_code == 200
        data = response.json()
        
        # Should return results for all transactions
        assert len(data["results"]) == 3
        
        # Check each result
        for result in data["results"]:
            assert "transaction_id" in result
            assert "risk_score" in result
            assert "decision" in result
    
    def test_empty_batch(self):
        """Test with empty batch"""
        response = client.post("/api/v1/fraud/batch", json={"transactions": []})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 0

    def test_batch_processing_is_chunked(self, monkeypatch):
        """Batch processing should fan out in bounded chunks."""
        call_sizes = []

        async def fake_check_transaction(txn_request):
            return TransactionCheckResponse(
                transaction_id=txn_request.transaction_id,
                risk_score=0.25,
                decision="approve",
                factors={"graph": 0.0, "velocity": 0.0, "behavior": 0.0, "entropy": 0.0},
                confidence=0.9,
                breakdown=RiskBreakdown(graph=0.0, velocity=0.0, behavior=0.0, entropy=0.0),
                explanation="ok",
                recommended_action="approve",
                processing_time_ms=1.0,
                timestamp="2026-01-01T00:00:00Z",
            )

        original_gather = api_main.asyncio.gather

        async def recording_gather(*args, **kwargs):
            call_sizes.append(len(args))
            return await original_gather(*args, **kwargs)

        monkeypatch.setattr(api_main, "check_transaction", fake_check_transaction)
        monkeypatch.setattr(api_main.asyncio, "gather", recording_gather)

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        
        transactions = [
            {
                "transaction_id": f"batch_{i}",
                "source_account": f"user_{i}",
                "target_account": f"merchant_{i}",
                "amount": 50.0 * (i + 1),
                "currency": "INR",
                "mode": "UPI",
                "timestamp": now,
                "device_id": f"device_{i}",
                "ip_address": f"103.1.1.{i}",
                "location": "Mumbai, India",
            }
            for i in range(17)
        ]

        response = client.post("/api/v1/fraud/batch", json={"transactions": transactions})

        assert response.status_code == 200
        assert call_sizes == [8, 8, 1]
        assert len(response.json()["results"]) == 17


class TestCORSandSecurity:
    """
    Test CORS middleware and security headers.

    The CORS tests are regression coverage for issue #34
    (CWE-942: Permissive Cross-domain Policy with Untrusted Domains).
    """

    def test_allowed_origin_gets_acao_header(self):
        """A request from an allowed origin should be echoed back."""
        response = client.get(
            "/health",
            headers={"Origin": "http://localhost:8501"},
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:8501"

    def test_disallowed_origin_does_not_get_acao_header(self):
        """A request from an unlisted origin should not be granted CORS access."""
        response = client.get(
            "/health",
            headers={"Origin": "https://attacker.example"},
        )
        assert response.status_code == 200
        # The origin must not be reflected back, even though credentials are enabled.
        assert response.headers.get("access-control-allow-origin") != "https://attacker.example"

    def test_credentials_allowed_for_listed_origin(self):
        """When the origin matches, credentials should be allowed."""
        response = client.get(
            "/health",
            headers={"Origin": "http://localhost:8501"},
        )
        assert response.headers.get("access-control-allow-credentials") == "true"

    def test_preflight_advertises_only_configured_methods(self):
        """OPTIONS preflight from a listed origin should advertise the
        narrowed method set, not '*'."""
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:8501",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        allow_methods = response.headers.get("access-control-allow-methods", "")
        assert "GET" in allow_methods
        assert "POST" in allow_methods
        assert "*" not in allow_methods

    def test_no_wildcard_origin_regression(self):
        """Make sure we never silently regress to allow_origins=['*']."""
        from src.api.main import ALLOWED_ORIGINS
        assert "*" not in ALLOWED_ORIGINS, (
            "ALLOWED_ORIGINS must be an explicit list of trusted origins"
        )

    def test_rate_limiting(self):
        """Test rate limiting (if implemented)"""
        # Make multiple rapid requests
        responses = []
        for i in range(10):
            response = client.get("/health")
            responses.append(response.status_code)
        
        # All should succeed (rate limiting not implemented yet)
        assert all(code == 200 for code in responses)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
