from unittest.mock import MagicMock, patch

import requests
import responses

from utils.webhook_alerts import (_send_payload_background,
                                  trigger_webhook_alert)


@responses.activate
def test_webhook_alerts_successful_delivery():
    url = "https://example.com/webhook"
    payload = {"event": "test", "value": 123}

    responses.add(responses.POST, url, json={"status": "ok"}, status=200)

    # Directly test the delivery function to wait synchronously
    _send_payload_background(url, payload, secret_key=None, timeout=2.0)

    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == url
    headers = responses.calls[0].request.headers
    assert headers["Content-Type"] == "application/json"
    assert "X-Sentinel-Signature" not in headers


@responses.activate
def test_webhook_alerts_with_signature():
    url = "https://example.com/webhook"
    payload = {"event": "test", "value": 123}
    secret = "my_secret_key"

    responses.add(responses.POST, url, json={"status": "ok"}, status=200)

    _send_payload_background(url, payload, secret_key=secret, timeout=2.0)

    assert len(responses.calls) == 1
    assert "X-Sentinel-Signature" in responses.calls[0].request.headers
    # Signature is hex digest of HMAC-SHA256 of payload with secret key
    sig = responses.calls[0].request.headers["X-Sentinel-Signature"]
    assert len(sig) == 64  # SHA-256 signature is 64 hex characters


@responses.activate
def test_webhook_alerts_timeout_handling():
    url = "https://example.com/webhook"
    payload = {"event": "test"}

    timeout_err = requests.exceptions.Timeout("Timeout occurred")
    responses.add(
        responses.POST,
        url,
        body=timeout_err
    )

    # Should not raise exception
    _send_payload_background(url, payload, secret_key=None, timeout=2.0)


@patch("threading.Thread")
def test_trigger_webhook_alert_non_blocking(mock_thread_cls):
    mock_thread_instance = MagicMock()
    mock_thread_cls.return_value = mock_thread_instance

    trigger_webhook_alert("https://example.com/webhook", {"event": "test"})

    mock_thread_cls.assert_called_once()
    mock_thread_instance.start.assert_called_once()
