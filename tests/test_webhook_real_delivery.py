"""Tests that webhook delivery reflects the endpoint's actual response.

Delivery was previously ``random.random() > 0.1`` and a retry was a second
coin flip -- nothing was ever sent, and the recorded status, response code
and success rate described the coin, not the endpoint.
"""

import inspect
import json

import pytest

from src.external_integration import webhook_manager as webhook_manager_module
from src.external_integration.models import WebhookEvent
from src.external_integration.store import IntegrationStore
from src.external_integration.webhook_manager import WebhookManager


class FakeResponse:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class RecordingTransport:
    """Captures each POST and returns a scripted response."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        outcome = (
            self.responses.pop(0) if self.responses
            else FakeResponse(200, "ok")
        )
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.fixture
def store():
    return IntegrationStore()


def manager(store, *responses):
    return WebhookManager(store=store, transport=RecordingTransport(*responses))


def register(mgr, secret=None, retry_count=3):
    return mgr.register_webhook(
        name="hook",
        endpoint="https://example.com/hook",
        events=[WebhookEvent.FRAUD_DETECTED],
        secret=secret,
        retry_count=retry_count,
    )


class TestDeterminism:
    """Delivery outcome must not be manufactured."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(webhook_manager_module)
        assert "import random" not in source

    def test_same_endpoint_response_gives_same_outcome(self, store):
        mgr = manager(store, FakeResponse(200), FakeResponse(200))
        register(mgr)

        first = mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {"a": 1})[0]
        second = mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {"a": 1})[0]

        assert first.status == second.status == "DELIVERED"


class TestDelivery:
    """The endpoint is actually contacted and its response recorded."""

    def test_payload_is_posted_to_the_endpoint(self, store):
        transport = RecordingTransport(FakeResponse(200, "ok"))
        mgr = WebhookManager(store=store, transport=transport)
        register(mgr)

        mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {"entity": "e1"})

        url, kwargs = transport.calls[0]
        assert url == "https://example.com/hook"
        assert json.loads(kwargs["data"]) == {"entity": "e1"}

    def test_success_records_the_real_status_code(self, store):
        mgr = manager(store, FakeResponse(202, "accepted"))
        register(mgr)

        delivery = mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})[0]

        assert delivery.status == "DELIVERED"
        assert delivery.response_code == 202
        assert delivery.response_body == "accepted"

    def test_error_status_is_a_failed_delivery(self, store):
        mgr = manager(store, FakeResponse(503, "busy"))
        register(mgr)

        delivery = mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})[0]

        assert delivery.status == "FAILED"
        assert delivery.response_code == 503

    def test_client_error_is_also_a_failure(self, store):
        mgr = manager(store, FakeResponse(404, "not found"))
        register(mgr)

        assert mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})[0].status == "FAILED"

    def test_unreachable_endpoint_fails_without_raising(self, store):
        mgr = manager(store, ConnectionError("refused"))
        register(mgr)

        delivery = mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})[0]

        assert delivery.status == "FAILED"
        assert delivery.response_code is None
        assert "refused" in delivery.response_body

    def test_webhook_timeout_is_passed_to_the_transport(self, store):
        transport = RecordingTransport(FakeResponse(200))
        mgr = WebhookManager(store=store, transport=transport)
        webhook = register(mgr)

        mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})

        assert transport.calls[0][1]["timeout"] == webhook.timeout_seconds


class TestSignature:
    """The stored secret is used to sign the payload."""

    def test_secret_produces_a_verifiable_signature(self, store):
        import hashlib
        import hmac

        transport = RecordingTransport(FakeResponse(200))
        mgr = WebhookManager(store=store, transport=transport)
        register(mgr, secret="s3cret")

        mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {"a": 1})

        _, kwargs = transport.calls[0]
        expected = hmac.new(
            b"s3cret", kwargs["data"].encode("utf-8"), hashlib.sha256,
        ).hexdigest()

        assert kwargs["headers"]["X-AegisGraph-Signature"] == f"sha256={expected}"

    def test_no_secret_means_no_signature_header(self, store):
        transport = RecordingTransport(FakeResponse(200))
        mgr = WebhookManager(store=store, transport=transport)
        register(mgr)

        mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})

        assert "X-AegisGraph-Signature" not in transport.calls[0][1]["headers"]

    def test_custom_headers_are_preserved(self, store):
        transport = RecordingTransport(FakeResponse(200))
        mgr = WebhookManager(store=store, transport=transport)
        mgr.register_webhook(
            name="hook",
            endpoint="https://example.com/hook",
            events=[WebhookEvent.FRAUD_DETECTED],
            headers={"X-Tenant": "acme"},
        )

        mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})

        assert transport.calls[0][1]["headers"]["X-Tenant"] == "acme"


class TestRetry:
    """A retry re-sends the payload and honours the retry budget."""

    def test_retry_resends_and_can_succeed(self, store):
        transport = RecordingTransport(FakeResponse(500), FakeResponse(200))
        mgr = WebhookManager(store=store, transport=transport)
        register(mgr)

        delivery = mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})[0]
        assert delivery.status == "FAILED"

        assert mgr.retry_delivery(delivery.delivery_id) is True
        assert delivery.status == "DELIVERED"
        assert len(transport.calls) == 2

    def test_retry_reports_the_endpoint_still_failing(self, store):
        mgr = manager(store, FakeResponse(500), FakeResponse(500))
        register(mgr)

        delivery = mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})[0]

        assert mgr.retry_delivery(delivery.delivery_id) is False
        assert delivery.status == "FAILED"

    def test_retry_budget_is_not_exceeded(self, store):
        transport = RecordingTransport(*[FakeResponse(500)] * 6)
        mgr = WebhookManager(store=store, transport=transport)
        register(mgr, retry_count=2)

        delivery = mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})[0]
        mgr.retry_delivery(delivery.delivery_id)
        mgr.retry_delivery(delivery.delivery_id)
        mgr.retry_delivery(delivery.delivery_id)

        # One initial attempt plus one retry, then the budget is spent.
        assert delivery.attempts == 2
        assert len(transport.calls) == 2


class TestStats:
    """Delivery stats now describe real outcomes."""

    def test_success_rate_follows_endpoint_responses(self, store):
        mgr = manager(
            store, FakeResponse(200), FakeResponse(500), FakeResponse(200),
            FakeResponse(500),
        )
        register(mgr)

        for _ in range(4):
            mgr.trigger_event(WebhookEvent.FRAUD_DETECTED, {})

        stats = mgr.get_delivery_stats()

        assert stats["total_deliveries"] == 4
        assert stats["delivered"] == 2
        assert stats["failed"] == 2
        assert stats["success_rate"] == pytest.approx(50.0)
