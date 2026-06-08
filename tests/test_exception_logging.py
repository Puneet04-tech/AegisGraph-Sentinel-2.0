"""
Tests for unified exception handling and structured audit logging.
"""

import asyncio
import json

import pytest
from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from fastapi.testclient import TestClient

from src.exceptions import (
    ErrorCode,
    ProcessingException,
    ServiceUnavailableException,
    ValidationException,
    build_error_payload,
    register_exception_handlers,
    register_observability_middleware,
)
from src.exceptions.error_responses import utc_timestamp
from src.exceptions.handlers import unhandled_exception_handler
from src.observability import (
    AuditLogger,
    StructuredLogger,
    clear_request_context,
    generate_request_id,
    get_request_id,
    set_request_context,
)
from src.api import main as api_main
from src.api.main import app


class TestErrorPayloadSerialization:
    def test_build_error_payload_structure(self):
        payload = build_error_payload(
            code=ErrorCode.VALIDATION_ERROR,
            type_name="ValidationException",
            message="Invalid transaction payload",
            request_id="req_abc123",
            timestamp="2026-05-21T10:30:00Z",
            details={"field": "amount"},
        )
        assert payload["error"]["code"] == "VALIDATION_ERROR"
        assert payload["error"]["type"] == "ValidationException"
        assert payload["error"]["message"] == "Invalid transaction payload"
        assert payload["error"]["request_id"] == "req_abc123"
        assert payload["error"]["timestamp"] == "2026-05-21T10:30:00Z"
        assert payload["error"]["details"] == {"field": "amount"}

    def test_aegis_exception_defaults(self):
        exc = ValidationException("bad input", details={"field": "x"})
        assert exc.status_code == 422
        assert exc.code == ErrorCode.VALIDATION_ERROR
        assert exc.type_name == "ValidationException"

    def test_utc_timestamp_format(self):
        ts = utc_timestamp()
        assert ts.endswith("Z")
        assert "T" in ts


class TestStdlibLoggingNamespace:
    def test_stdlib_logging_not_shadowed(self):
        import logging as stdlib_logging

        assert stdlib_logging.__name__ == "logging"
        assert hasattr(stdlib_logging, "getLogger")
        assert stdlib_logging.getLogger("stdlib.namespace.test").name == "stdlib.namespace.test"

    def test_observability_package_imports(self):
        from src.observability.audit_logger import AuditLogger
        from src.observability.structured_logger import StructuredLogger

        assert AuditLogger is not None
        assert StructuredLogger is not None


class TestStructuredLogging:
    def test_structured_log_json_fields(self, capsys):
        logger = StructuredLogger("test.module")
        set_request_context(request_id="req_test001", correlation_id="corr_test001")
        logger.info("hello", event_type="unit_test", metadata={"k": 1})
        clear_request_context()

        captured = capsys.readouterr().out.strip().splitlines()[-1]
        record = json.loads(captured)
        assert record["request_id"] == "req_test001"
        assert record["correlation_id"] == "corr_test001"
        assert record["module"] == "test.module"
        assert record["event_type"] == "unit_test"
        assert record["severity"] == "INFO"
        assert record["message"] == "hello"
        assert record["metadata"] == {"k": 1}
        assert "timestamp" in record

    def test_generate_request_id_prefix(self):
        rid = generate_request_id()
        assert rid.startswith("req_")


class TestAuditLogging:
    def test_fraud_decision_audit_event(self, capsys):
        audit = AuditLogger(module="test.audit")
        audit.log_fraud_decision(
            transaction_id="TXN-1",
            decision="REVIEW",
            risk_score=0.72,
            triggered_modules=["graph", "velocity"],
        )
        record = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert record["event_type"] == "fraud_decision"
        assert record["severity"] == "AUDIT"
        assert record["metadata"]["transaction_id"] == "TXN-1"
        assert record["metadata"]["risk_score"] == 0.72
        assert record["metadata"]["triggered_modules"] == ["graph", "velocity"]


class TestExceptionHandlersApp:
    @pytest.fixture
    def handler_app(self):
        test_app = FastAPI()
        register_exception_handlers(test_app)
        register_observability_middleware(test_app)

        @test_app.get("/ok")
        async def ok():
            return {"status": "ok"}

        @test_app.get("/validation")
        async def validation():
            raise ValidationException("Invalid payload", details={"field": "amount"})

        @test_app.get("/http-503")
        async def unavailable():
            raise HTTPException(status_code=503, detail="Service down")

        @test_app.get("/boom")
        async def boom():
            raise RuntimeError("unexpected")

        return test_app

    def test_validation_exception_handler(self, handler_app):
        client = TestClient(handler_app)
        response = client.get("/validation")
        assert response.status_code == 422
        body = response.json()
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert body["error"]["type"] == "ValidationException"
        assert "request_id" in body["error"]
        assert response.headers.get("X-Request-ID")

    def test_http_exception_preserves_status(self, handler_app):
        client = TestClient(handler_app)
        response = client.get("/http-503")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "SERVICE_UNAVAILABLE"

    def test_unhandled_exception_handler_direct(self):
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/boom",
            "headers": [],
            "query_string": b"",
        }
        request = Request(scope)
        request.state.request_id = "req_direct_1"

        async def _run():
            return await unhandled_exception_handler(request, RuntimeError("unexpected"))

        response = asyncio.run(_run())
        assert response.status_code == 500
        body = json.loads(response.body)
        assert body["error"]["code"] == "INTERNAL_ERROR"
        assert body["error"]["request_id"] == "req_direct_1"

    def test_unknown_exception_safe_response(self, handler_app):
        client = TestClient(handler_app, raise_server_exceptions=False)
        response = client.get("/boom")
        assert response.status_code == 500
        body = response.json()
        assert body["error"]["code"] == "INTERNAL_ERROR"
        assert body["error"]["message"] == "Internal server error"
        assert body["error"]["details"] == {}
        assert response.headers.get("X-Request-ID")


class TestApiIntegration:
    def test_request_id_propagation_header(self):
        client = TestClient(app)
        response = client.get("/health", headers={"X-Request-ID": "req_custom_99"})
        assert response.status_code == 200
        assert response.headers.get("X-Request-ID") == "req_custom_99"

    def test_correlation_id_persistence(self):
        client = TestClient(app)
        response = client.get(
            "/health",
            headers={
                "X-Request-ID": "req_corr_a",
                "X-Correlation-ID": "corr_custom_b",
            },
        )
        assert response.headers.get("X-Request-ID") == "req_corr_a"
        assert response.headers.get("X-Correlation-ID") == "corr_custom_b"

    def test_validation_error_standardized_json(self):
        client = TestClient(app)
        response = client.post("/api/v1/fraud/check", json={"transaction_id": "bad"})
        assert response.status_code == 422
        body = response.json()
        assert "error" in body
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert "validation_errors" in body["error"]["details"]

    def test_successful_fraud_check_unchanged_shape(self, monkeypatch):
        def fake_compute_risk_score(transaction: dict, biometrics: dict = None, **kwargs):
            return {
                "risk_score": 0.15,
                "decision": "ALLOW",
                "confidence": 0.9,
                "breakdown": {"graph": 0.0, "velocity": 0.0, "behavior": 0.0, "entropy": 0.0},
            }

        def fake_generate_explanation(transaction: dict = None, risk_result: dict = None, **kwargs):
            return {
                "explanation": "Low risk",
                "recommended_action": "ACTION_ALLOW",
            }

        monkeypatch.setattr("src.api.main.compute_risk_score", fake_compute_risk_score)
        monkeypatch.setattr("src.api.main.generate_explanation", fake_generate_explanation)

        client = TestClient(app)
        payload = {
            "transaction_id": "compat_001",
            "amount": 100.0,
            "timestamp": 1779883200.0,
            "from_account": "user_a",
            "to_account": "user_b",
        }
        response = client.post("/api/v1/fraud/check", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["transaction_id"] == "compat_001"
        assert "risk_score" in data
        assert "decision" in data
        assert "factors" in data
        assert "explanation" in data

    def test_http_exception_standardized_json(self, monkeypatch):
        class _BoomOracle:
            def generate_explanation(self, *args, **kwargs):
                raise RuntimeError("oracle internal failure")

        monkeypatch.setitem(api_main.app.dependency_overrides, api_main.get_aegis_oracle, lambda: _BoomOracle())
        client = TestClient(app)
        response = client.post("/api/v1/explain", json={"decision": "BLOCK", "risk_score": 0.9})
        assert response.status_code in (503, 500)
        body = response.json()
        assert "error" in body
        assert "code" in body["error"]
        assert "request_id" in body["error"]

    def test_processing_exception_mapping(self):
        exc = ProcessingException("Scoring failed", details={"stage": "inference"})
        assert exc.code == ErrorCode.PROCESSING_ERROR
        assert exc.status_code == 500

    def test_service_unavailable_exception(self):
        exc = ServiceUnavailableException("Oracle offline")
        assert exc.status_code == 503
        assert exc.code == ErrorCode.SERVICE_UNAVAILABLE

    def test_request_context_helpers(self):
        set_request_context(request_id="req_ctx", correlation_id="corr_ctx")
        assert get_request_id() == "req_ctx"
        clear_request_context()
        assert get_request_id() is None
