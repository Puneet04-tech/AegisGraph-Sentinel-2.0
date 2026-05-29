"""
Unit tests for API endpoints
"""
# Working on API endpoint testing

import pytest
import asyncio
from fastapi.testclient import TestClient
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api import main as api_main
from src.api.main import app, state
from src.api.security import require_api_key
from src.api.schemas import RiskBreakdown, TransactionCheckResponse, LegalExportRequest


client = TestClient(app)

_TEST_API_KEY = "test-api-key-for-health-tests"
_TEST_API_KEY_HASH = hashlib.sha256(_TEST_API_KEY.encode("utf-8")).hexdigest()


def _enable_real_api_key_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_API_KEY_HASHES", _TEST_API_KEY_HASH)
    app.dependency_overrides.pop(require_api_key, None)


def _clear_rate_limit_storage():
    limiter = api_main.limiter
    for storage_attr in ("storage", "_storage"):
        storage = getattr(limiter, storage_attr, None)
        if storage is None:
            continue

        reset = getattr(storage, "reset", None)
        if callable(reset):
            reset()
            return

        for candidate in (storage, getattr(storage, "storage", None)):
            if candidate is None:
                continue

            clear = getattr(candidate, "clear", None)
            if callable(clear):
                try:
                    clear()
                except TypeError:
                    continue
                return


class _RecordingLoop:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    async def run_in_executor(self, executor, func, *args):
        self.calls.append((executor, func, args))
        return self.results[len(self.calls) - 1]


class _FakeBlockchainManager:
    def export_for_legal_proceedings(self, evidence_id, case_number, requesting_authority):
        return {
            "package": {
                "evidence_id": evidence_id,
                "case_number": case_number,
                "requesting_authority": requesting_authority,
            },
            "chain_of_custody": [{"event": "legal_export_generated"}],
            "attestations": [{"validator": "validator-1"}],
            "export_timestamp": "2026-05-27T00:00:00Z",
            "authorized_by": requesting_authority,
        }


class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_check_public_is_minimal(self):
        """Test /health endpoint returns only sanitized public fields"""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "AegisGraph Sentinel"
        assert "model_loaded" not in data
        assert "graph_loaded" not in data
        assert "innovations_available" not in data
        assert "requests_processed" not in data
        assert "uptime_seconds" not in data

    def test_api_v1_health_public_is_minimal(self):
        """Test /api/v1/health returns only sanitized public fields"""
        response = client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "AegisGraph Sentinel"
        assert "model_loaded" not in data
        assert "graph_loaded" not in data
        assert "innovations_available" not in data
        assert "requests_processed" not in data
        assert "uptime_seconds" not in data

    def test_verbose_health_requires_auth(self, monkeypatch):
        """Verbose health requests must be rejected without an API key."""
        _enable_real_api_key_gate(monkeypatch)
        response = client.get("/health?verbose=true")

        assert response.status_code == 401

    def test_verbose_health_returns_details_when_authenticated(self, monkeypatch):
        """Verbose health requests should expose operational data only with auth."""
        _enable_real_api_key_gate(monkeypatch)
        headers = {"X-API-Key": _TEST_API_KEY}

        response = client.get("/health?verbose=true", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "AegisGraph Sentinel"
        assert "model_loaded" in data
        assert "graph_loaded" in data
        assert "innovations_available" in data
        assert "requests_processed" in data
        assert "uptime_seconds" in data

    def test_api_v1_verbose_health_returns_details_when_authenticated(self, monkeypatch):
        """Verbose v1 health requests should expose operational data only with auth."""
        _enable_real_api_key_gate(monkeypatch)
        headers = {"X-API-Key": _TEST_API_KEY}

        response = client.get("/api/v1/health?verbose=true", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "AegisGraph Sentinel"
        assert "model_loaded" in data
        assert "graph_loaded" in data
        assert "innovations_available" in data
        assert "requests_processed" in data
        assert "uptime_seconds" in data


class TestStatsEndpoint:
    """Test statistics endpoint"""
    
    def test_get_stats_requires_auth(self, monkeypatch):
        """Test /stats endpoint requires an API key"""
        _enable_real_api_key_gate(monkeypatch)
        response = client.get("/stats")

        assert response.status_code == 401

    def test_get_stats_with_auth(self, monkeypatch):
        """Test /stats endpoint with an API key"""
        _enable_real_api_key_gate(monkeypatch)
        headers = {"X-API-Key": _TEST_API_KEY}
        response = client.get("/stats", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Check expected fields
        assert "total_checks" in data
        assert "flagged_transactions" in data
        assert "average_response_time" in data
        assert "uptime_seconds" in data


class TestLegalExportSecurity:
    """Test legal evidence export hardening."""

    def _enable_legal_export(self, monkeypatch):
        monkeypatch.setattr(api_main, "INNOVATIONS_AVAILABLE", True)
        monkeypatch.setattr(api_main.state, "blockchain_manager", _FakeBlockchainManager())
        monkeypatch.setenv("AEGIS_LEGAL_EXPORT_TOKEN_HASH", hashlib.sha256(b"legal-token").hexdigest())
        _clear_rate_limit_storage()

    def _headers(self, token="legal-token", timestamp=None, use_fallback=False):
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        timestamp_header = timestamp.isoformat().replace("+00:00", "Z")
        headers = {"X-Request-Timestamp": timestamp_header}
        if use_fallback:
            headers["X-Legal-Export-Token"] = token
        else:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def test_legal_export_request_schema_has_no_token(self):
        assert "authorization_token" not in LegalExportRequest.model_fields

    def test_legal_export_requires_auth_header(self, monkeypatch):
        self._enable_legal_export(monkeypatch)

        response = client.post(
            "/api/v1/blockchain/export",
            json={
                "evidence_id": "EVID-001",
                "case_number": "CASE-001",
                "requesting_authority": "Police Dept",
            },
            headers={"X-Request-Timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")},
        )

        assert response.status_code == 401

    def test_legal_export_rejects_invalid_token(self, monkeypatch):
        self._enable_legal_export(monkeypatch)

        response = client.post(
            "/api/v1/blockchain/export",
            json={
                "evidence_id": "EVID-001",
                "case_number": "CASE-001",
                "requesting_authority": "Police Dept",
            },
            headers=self._headers(token="wrong-token"),
        )

        assert response.status_code == 403

    def test_legal_export_accepts_valid_token(self, monkeypatch):
        self._enable_legal_export(monkeypatch)

        response = client.post(
            "/api/v1/blockchain/export",
            json={
                "evidence_id": "EVID-001",
                "case_number": "CASE-001",
                "requesting_authority": "Police Dept",
            },
            headers=self._headers(),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["evidence_id"] == "EVID-001"
        assert data["case_number"] == "CASE-001"

    def test_legal_export_rejects_expired_timestamp(self, monkeypatch):
        self._enable_legal_export(monkeypatch)

        expired_timestamp = datetime.now(timezone.utc) - timedelta(minutes=6)
        response = client.post(
            "/api/v1/blockchain/export",
            json={
                "evidence_id": "EVID-001",
                "case_number": "CASE-001",
                "requesting_authority": "Police Dept",
            },
            headers=self._headers(timestamp=expired_timestamp),
        )

        assert response.status_code == 401

    def test_legal_export_is_rate_limited(self, monkeypatch):
        self._enable_legal_export(monkeypatch)

        payload = {
            "evidence_id": "EVID-001",
            "case_number": "CASE-001",
            "requesting_authority": "Police Dept",
        }

        for _ in range(5):
            response = client.post(
                "/api/v1/blockchain/export",
                json=payload,
                headers=self._headers(),
            )
            assert response.status_code == 200

        limited_response = client.post(
            "/api/v1/blockchain/export",
            json=payload,
            headers=self._headers(),
        )

        assert limited_response.status_code == 429


class TestFraudCheckEndpoint:
    """Test fraud check endpoint"""
    
    def test_low_risk_transaction(self):
        """Test with a low-risk transaction"""
        transaction = {
            "transaction_id": "test_001",
            "amount": 50.0,
            "timestamp": 1779883200.0,
            "from_account": "user_1",
            "to_account": "merchant_1",
            "transaction_type": "payment",
            "metadata": {
                "location": "US",
                "device_id": "device_1"
            }
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
        transaction = {
            "transaction_id": "test_002",
            "amount": 10000.0,
            "timestamp": 1779883200.0,
            "from_account": "new_user",
            "to_account": "unknown_merchant",
            "transaction_type": "transfer",
            "metadata": {
                "location": "XX",
                "device_id": "new_device"
            }
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
        transaction = {
            "transaction_id": "test_003",
            "amount": 100.0,
            "timestamp": 1779883200.0,
            "from_account": "user_1",
            "to_account": "merchant_1",
            "transaction_type": "payment",
            "biometrics": {
                "keystroke_events": [
                    {"key": "a", "timestamp": 0.0, "event_type": "keydown"},
                    {"key": "a", "timestamp": 0.1, "event_type": "keyup"}
                ],
                "mouse_movements": []
            }
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

        transaction = {
            "transaction_id": "test_allow_001",
            "amount": 100.0,
            "timestamp": 1779883200.0,
            "from_account": "user_allow",
            "to_account": "merchant_allow",
            "transaction_type": "payment"
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

        transactions = [
            {
                "transaction_id": "batch_allow",
                "amount": 50.0,
                "timestamp": 1779883200.0,
                "from_account": "user_allow",
                "to_account": "merchant_allow",
                "transaction_type": "payment",
            },
            {
                "transaction_id": "batch_review",
                "amount": 75.0,
                "timestamp": 1779883260.0,
                "from_account": "user_review",
                "to_account": "merchant_review",
                "transaction_type": "payment",
            },
            {
                "transaction_id": "batch_block",
                "amount": 100.0,
                "timestamp": 1779883320.0,
                "from_account": "user_block",
                "to_account": "merchant_block",
                "transaction_type": "payment",
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
        transactions = [
            {
                "transaction_id": f"batch_{i}",
                "amount": 50.0 * (i + 1),
                "timestamp": 1779883200.0 + i * 60,
                "from_account": f"user_{i}",
                "to_account": f"merchant_{i}",
                "transaction_type": "payment"
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

        transactions = [
            {
                "transaction_id": f"batch_{i}",
                "amount": 50.0 * (i + 1),
                "timestamp": 1779883200.0 + i * 60,
                "from_account": f"user_{i}",
                "to_account": f"merchant_{i}",
                "transaction_type": "payment",
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


class TestAsyncExplainabilityOffload:
    def test_oracle_explanations_use_executor(self, monkeypatch):
        """Oracle explanation generation should be offloaded from the request thread."""
        class _FakeOracle:
            def generate_explanation(self, **kwargs):
                return {"oracle_reasoning": "background result"}

        fake_oracle = _FakeOracle()

        def fake_optional_get(name):
            if name == "aegis_oracle":
                return fake_oracle
            return None

        monkeypatch.setattr(api_main, "INNOVATIONS_AVAILABLE", True)
        monkeypatch.setattr(api_main.state.services, "optional_get", fake_optional_get)
        oracle_loop = _RecordingLoop([{"oracle_reasoning": "background result"}])
        monkeypatch.setattr(api_main.asyncio, "get_running_loop", lambda: oracle_loop)

        oracle_request = api_main.OracleExplainRequest(
            transaction={"transaction_id": "txn-380"},
            risk_assessment={"decision": "ALLOW", "risk_score": 0.12, "confidence": 0.91},
            risk_breakdown={"graph": 0.1, "velocity": 0.1, "behavior": 0.1, "entropy": 0.1},
            innovations_triggered=["oracle"],
        )

        oracle_response = asyncio.run(api_main.oracle_explain_detailed(oracle_request))

        assert len(oracle_loop.calls) == 1
        assert oracle_loop.calls[0][1].keywords["transaction"] == {"transaction_id": "txn-380"}
        assert oracle_response["oracle_reasoning"] == {"oracle_reasoning": "background result"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
