"""Tests that connections are actually established and exercised.

connect(), health_check() and execute_request() were coin flips that never
contacted the endpoint, and the stored auth_config was never used.
"""

import base64
import inspect

import pytest

from src.external_integration import connector_framework as connector_framework_module
from src.external_integration.connector_framework import ConnectorFramework
from src.external_integration.models import AuthType, ConnectorType, IntegrationStatus
from src.external_integration.store import IntegrationStore


class FakeResponse:
    def __init__(self, status_code=200, text="{}"):
        self.status_code = status_code
        self.text = text

    def json(self):
        import json
        return json.loads(self.text)


class RecordingTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        outcome = self.responses.pop(0) if self.responses else FakeResponse()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.fixture
def store():
    return IntegrationStore()


def framework(store, *responses):
    return ConnectorFramework(store=store, transport=RecordingTransport(*responses))


def make_connection(fw, auth_type=AuthType.NONE, auth_config=None):
    return fw.create_connection(
        name="System",
        connector_type=ConnectorType.REST_API,
        endpoint="https://api.example.com",
        auth_type=auth_type,
        auth_config=auth_config,
    )


class TestDeterminism:
    """Connection outcomes must not be manufactured."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(connector_framework_module)
        assert "import random" not in source

    def test_same_endpoint_response_gives_the_same_outcome(self, store):
        fw = framework(store, FakeResponse(200), FakeResponse(200))
        connection = make_connection(fw)

        assert fw.connect(connection.connection_id) is True
        assert fw.connect(connection.connection_id) is True


class TestConnect:
    """The endpoint is contacted."""

    def test_reachable_endpoint_connects(self, store):
        fw = framework(store, FakeResponse(200))
        connection = make_connection(fw)

        assert fw.connect(connection.connection_id) is True
        assert connection.status == IntegrationStatus.ACTIVE
        assert connection.health_status == "HEALTHY"

    def test_error_response_fails_the_connection(self, store):
        fw = framework(store, FakeResponse(503))
        connection = make_connection(fw)

        assert fw.connect(connection.connection_id) is False
        assert connection.status == IntegrationStatus.ERROR

    def test_unreachable_endpoint_fails_without_raising(self, store):
        fw = framework(store, ConnectionError("dns failure"))
        connection = make_connection(fw)

        assert fw.connect(connection.connection_id) is False

    def test_the_endpoint_is_the_one_configured(self, store):
        transport = RecordingTransport(FakeResponse(200))
        fw = ConnectorFramework(store=store, transport=transport)
        connection = make_connection(fw)

        fw.connect(connection.connection_id)

        assert transport.calls[0][1] == "https://api.example.com"


class TestAuthentication:
    """Stored credentials are actually sent."""

    def _headers(self, store, auth_type, auth_config):
        transport = RecordingTransport(FakeResponse(200))
        fw = ConnectorFramework(store=store, transport=transport)
        connection = make_connection(fw, auth_type, auth_config)
        fw.connect(connection.connection_id)
        return transport.calls[0][2]["headers"]

    def test_api_key_is_sent(self, store):
        headers = self._headers(store, AuthType.API_KEY, {"api_key": "k1"})

        assert headers["X-API-Key"] == "k1"

    def test_api_key_header_name_is_configurable(self, store):
        headers = self._headers(
            store, AuthType.API_KEY, {"api_key": "k1", "header": "X-Splunk-Key"},
        )

        assert headers["X-Splunk-Key"] == "k1"

    def test_bearer_token_is_sent(self, store):
        headers = self._headers(store, AuthType.BEARER, {"token": "t0ken"})

        assert headers["Authorization"] == "Bearer t0ken"

    def test_basic_auth_is_encoded(self, store):
        headers = self._headers(
            store, AuthType.BASIC, {"username": "u", "password": "p"},
        )

        expected = base64.b64encode(b"u:p").decode("ascii")
        assert headers["Authorization"] == f"Basic {expected}"

    def test_no_auth_sends_no_authorization(self, store):
        headers = self._headers(store, AuthType.NONE, None)

        assert "Authorization" not in headers


class TestHealthCheck:
    """Health reflects the endpoint."""

    def test_healthy_endpoint(self, store):
        fw = framework(store, FakeResponse(200), FakeResponse(200))
        connection = make_connection(fw)
        fw.connect(connection.connection_id)

        health = fw.health_check(connection.connection_id)

        assert health["health_status"] == "HEALTHY"
        assert health["error"] is None

    def test_failing_endpoint_marks_the_connection_unhealthy(self, store):
        fw = framework(store, FakeResponse(200), FakeResponse(500))
        connection = make_connection(fw)
        fw.connect(connection.connection_id)

        health = fw.health_check(connection.connection_id)

        assert health["health_status"] == "UNHEALTHY"
        assert connection.status == IntegrationStatus.ERROR

    def test_latency_is_measured(self, store):
        fw = framework(store, FakeResponse(200))
        connection = make_connection(fw)

        assert fw.health_check(connection.connection_id)["latency_ms"] >= 0

    def test_health_summary_follows_real_checks(self, store):
        fw = framework(store, FakeResponse(200), ConnectionError("down"))
        healthy = make_connection(fw)
        unhealthy = make_connection(fw)

        fw.connect(healthy.connection_id)
        fw.connect(unhealthy.connection_id)

        summary = fw.get_connection_health_summary()
        assert summary["healthy"] == 1
        assert summary["unhealthy"] == 1


class TestExecuteRequest:
    """Requests are sent and their real outcome reported."""

    def _active(self, store, *responses):
        fw = framework(store, FakeResponse(200), *responses)
        connection = make_connection(fw)
        fw.connect(connection.connection_id)
        return fw, connection

    def test_request_reaches_the_right_url(self, store):
        transport = RecordingTransport(FakeResponse(200), FakeResponse(200))
        fw = ConnectorFramework(store=store, transport=transport)
        connection = make_connection(fw)
        fw.connect(connection.connection_id)

        fw.execute_request(connection.connection_id, "POST", "/search")

        method, url, _ = transport.calls[1]
        assert method == "POST"
        assert url == "https://api.example.com/search"

    def test_successful_response_is_reported(self, store):
        fw, connection = self._active(store, FakeResponse(200, '{"hits": 3}'))

        result = fw.execute_request(connection.connection_id, "GET", "/search")

        assert result["success"] is True
        assert result["status_code"] == 200
        assert result["data"] == {"hits": 3}

    def test_error_response_is_reported(self, store):
        fw, connection = self._active(store, FakeResponse(500, "boom"))

        result = fw.execute_request(connection.connection_id, "GET", "/search")

        assert result["success"] is False
        assert result["status_code"] == 500

    def test_transport_failure_does_not_raise(self, store):
        fw, connection = self._active(store, TimeoutError("timed out"))

        result = fw.execute_request(connection.connection_id, "GET", "/search")

        assert result["success"] is False
        assert result["status_code"] is None
        assert "timed out" in result["error"]

    def test_duration_is_measured_not_invented(self, store):
        fw, connection = self._active(store, FakeResponse(200))

        result = fw.execute_request(connection.connection_id, "GET", "/search")

        # The old code reported random.uniform(10, 500) ms for a call that
        # never happened; a real local call is far faster than 10ms.
        assert result["duration_ms"] < 10

    def test_inactive_connection_is_refused(self, store):
        fw = framework(store)
        connection = make_connection(fw)

        assert "error" in fw.execute_request(connection.connection_id, "GET", "/x")
