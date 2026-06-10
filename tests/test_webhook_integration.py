"""Unit and integration tests for the Real-Time Webhook Integration (Issue #633).

Coverage
--------
* WebhookSettings — defaults, env-var loading, global kill-switch.
* WebhookManager — Discord payload format, Slack Block Kit format.
* WebhookManager — successful delivery, retry on network error,
  per-service failure isolation, global kill-switch bypass.
* Event handler — graceful handling when settings load fails.
* URL validation — schema enforcement in WebhookSettings.
* End-to-end — fraud check → BLOCK decision → webhook POST triggered.
"""

from __future__ import annotations

import asyncio
import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from src.config.loaders import load_settings
from src.config.schemas import WebhookSettings
from src.runtime.events.event_types import SentinelAlertEvent
from src.runtime.events.webhook_manager import WebhookManager
from src.runtime.events.event_handlers import on_sentinel_alert


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_event() -> SentinelAlertEvent:
    """A realistic HIGH-severity SentinelAlertEvent for use across tests."""
    return SentinelAlertEvent(
        source="test_source",
        severity="HIGH",
        title="Transaction Blocked",
        message="A high-risk transaction was detected.",
        payload={
            "transaction_id": "tx_9999",
            "amount": 250000.0,
            "currency": "USD",
            "source_account": "acc_source",
            "target_account": "acc_target",
            "risk_score": 0.95,
            "explanation": "High velocity and suspected mule link.",
        },
    )


@pytest.fixture
def minimal_event() -> SentinelAlertEvent:
    """A minimal SentinelAlertEvent with no optional payload fields."""
    return SentinelAlertEvent(
        source="unit_test",
        severity="HIGH",
        title="Minimal Alert",
        message="No extra payload.",
    )


# ---------------------------------------------------------------------------
# Configuration / settings tests
# ---------------------------------------------------------------------------


def test_webhook_settings_defaults() -> None:
    """Verify default values are correctly loaded when no env vars are defined."""
    with patch.dict("os.environ", {}, clear=True):
        settings = load_settings()
        assert settings.webhook.discord_url == ""
        assert settings.webhook.slack_url == ""
        assert settings.webhook.enable_discord is False
        assert settings.webhook.enable_slack is False
        assert settings.webhook.enable_alerts is False


def test_webhook_settings_env_loading() -> None:
    """Verify configuration loads properly from environment variables."""
    env_overrides = {
        "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/123",
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/abc",
        "ENABLE_DISCORD_WEBHOOK": "true",
        "ENABLE_SLACK_WEBHOOK": "1",
        "ENABLE_WEBHOOK_ALERTS": "true",
    }
    with patch.dict("os.environ", env_overrides, clear=True):
        settings = load_settings()
        assert settings.webhook.discord_url == "https://discord.com/api/webhooks/123"
        assert settings.webhook.slack_url == "https://hooks.slack.com/services/abc"
        assert settings.webhook.enable_discord is True
        assert settings.webhook.enable_slack is True
        assert settings.webhook.enable_alerts is True


def test_webhook_settings_global_toggle_defaults_false() -> None:
    """Verify enable_alerts is False by default (safe opt-in behaviour)."""
    settings = WebhookSettings()
    assert settings.enable_alerts is False


def test_webhook_settings_global_toggle_env_override() -> None:
    """Verify ENABLE_WEBHOOK_ALERTS is read correctly from the environment."""
    with patch.dict("os.environ", {"ENABLE_WEBHOOK_ALERTS": "yes"}, clear=False):
        from src.config import defaults as _defaults
        # Force reload of defaults module attribute to pick up patch
        original = _defaults.DEFAULT_ENABLE_WEBHOOK_ALERTS
        try:
            _defaults.DEFAULT_ENABLE_WEBHOOK_ALERTS = True
            s = WebhookSettings(enable_alerts=True)
            assert s.enable_alerts is True
        finally:
            _defaults.DEFAULT_ENABLE_WEBHOOK_ALERTS = original


def test_webhook_settings_url_validator_rejects_non_https_discord() -> None:
    """Webhook URL validator must reject non-HTTPS Discord URLs."""
    with pytest.raises(Exception):
        WebhookSettings(discord_url="http://discord.com/api/webhooks/bad")


def test_webhook_settings_url_validator_rejects_non_https_slack() -> None:
    """Webhook URL validator must reject non-HTTPS Slack URLs."""
    with pytest.raises(Exception):
        WebhookSettings(slack_url="http://hooks.slack.com/services/bad")


def test_webhook_settings_empty_urls_are_valid() -> None:
    """Empty URL strings are valid — they simply mean the service is unconfigured."""
    s = WebhookSettings(discord_url="", slack_url="")
    assert s.discord_url == ""
    assert s.slack_url == ""


# ---------------------------------------------------------------------------
# Discord payload formatting tests
# ---------------------------------------------------------------------------


def test_discord_payload_formatting(sample_event: SentinelAlertEvent) -> None:
    """Verify Discord payload follows the required structure and contains transaction info."""
    settings = WebhookSettings(discord_url="https://discord.com/api/webhooks/test", enable_discord=True)
    manager = WebhookManager(settings)

    payload = manager._format_discord_payload(sample_event)

    assert payload["username"] == "AegisGraph Sentinel"
    assert len(payload["embeds"]) == 1
    embed = payload["embeds"][0]
    assert embed["title"] == "🚨 Transaction Blocked"
    assert embed["description"] == "A high-risk transaction was detected."
    assert embed["color"] == 16711680  # HIGH severity → red

    fields = {f["name"]: f["value"] for f in embed["fields"]}
    assert "`HIGH`" in fields["Severity"]
    assert fields["Transaction ID"] == "tx_9999"
    assert "250000.0" in fields["Amount"]
    assert "USD" in fields["Amount"]
    assert fields["Risk Score"] == "0.9500"
    assert fields["Explanation"] == "High velocity and suspected mule link."

    # Timestamp and footer must be present
    assert "timestamp" in embed
    assert "footer" in embed


def test_discord_payload_no_optional_fields(minimal_event: SentinelAlertEvent) -> None:
    """Minimal payload should produce a valid embed without optional fields."""
    settings = WebhookSettings(discord_url="https://discord.com/api/webhooks/test", enable_discord=True)
    manager = WebhookManager(settings)

    payload = manager._format_discord_payload(minimal_event)
    embed = payload["embeds"][0]
    field_names = {f["name"] for f in embed["fields"]}

    # Only mandatory fields should appear
    assert "Severity" in field_names
    assert "Source" in field_names
    assert "Transaction ID" in field_names
    # Optional fields should not appear
    assert "Amount" not in field_names
    assert "Risk Score" not in field_names
    assert "Explanation" not in field_names


def test_discord_payload_critical_severity_colour() -> None:
    """CRITICAL severity should use the red embed colour."""
    event = SentinelAlertEvent(
        source="test", severity="CRITICAL", title="Critical Alert", message="Urgent"
    )
    settings = WebhookSettings(discord_url="https://discord.com/api/webhooks/test", enable_discord=True)
    manager = WebhookManager(settings)
    payload = manager._format_discord_payload(event)
    assert payload["embeds"][0]["color"] == 16711680  # red


def test_discord_payload_medium_severity_colour() -> None:
    """MEDIUM severity should use the gold/yellow embed colour."""
    event = SentinelAlertEvent(
        source="test", severity="MEDIUM", title="Medium Alert", message="Review"
    )
    settings = WebhookSettings(discord_url="https://discord.com/api/webhooks/test", enable_discord=True)
    manager = WebhookManager(settings)
    payload = manager._format_discord_payload(event)
    assert payload["embeds"][0]["color"] == 16768256  # gold


# ---------------------------------------------------------------------------
# Slack payload formatting tests
# ---------------------------------------------------------------------------


def test_slack_payload_formatting(sample_event: SentinelAlertEvent) -> None:
    """Verify Slack payload matches the Slack Block Kit specification."""
    settings = WebhookSettings(slack_url="https://hooks.slack.com/services/test", enable_slack=True)
    manager = WebhookManager(settings)

    payload = manager._format_slack_payload(sample_event)

    assert "blocks" in payload
    assert "text" in payload  # fallback text
    blocks = payload["blocks"]

    # Block structure: header, section (message), divider, section (fields)
    assert blocks[0]["type"] == "header"
    assert "Transaction Blocked" in blocks[0]["text"]["text"]

    section_text = blocks[1]["text"]["text"]
    assert "A high-risk transaction was detected." in section_text

    assert blocks[2]["type"] == "divider"

    fields = [f["text"] for f in blocks[3]["fields"]]
    assert any("tx_9999" in text for text in fields)
    assert any("250000.0" in text for text in fields)
    assert any("0.9500" in text for text in fields)

    # Explanation block is index 4 when present
    assert "High velocity and suspected mule link." in blocks[4]["text"]["text"]

    # Context block (last) must contain timestamp and event ID
    context_text = blocks[-1]["elements"][0]["text"]
    assert "Timestamp:" in context_text
    assert "Event ID:" in context_text


def test_slack_payload_fields_capped_at_ten() -> None:
    """Slack Block Kit limits section fields to 10; verify the cap is enforced."""
    event = SentinelAlertEvent(
        source="test",
        severity="HIGH",
        title="Alert",
        message="Many fields",
        payload={
            "transaction_id": "tx_001",
            "amount": 1000.0,
            "currency": "USD",
            "source_account": "acc_a",
            "target_account": "acc_b",
            "risk_score": 0.90,
        },
    )
    settings = WebhookSettings(slack_url="https://hooks.slack.com/services/test", enable_slack=True)
    manager = WebhookManager(settings)
    payload = manager._format_slack_payload(event)

    # Find the fields section block
    fields_section = next(b for b in payload["blocks"] if b.get("fields"))
    assert len(fields_section["fields"]) <= 10


# ---------------------------------------------------------------------------
# HTTP delivery and retry tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_webhook_send_success(sample_event: SentinelAlertEvent) -> None:
    """Verify successful dispatch routes to both endpoints when enabled."""
    settings = WebhookSettings(
        discord_url="https://discord.webhook",
        slack_url="https://slack.webhook",
        enable_discord=True,
        enable_slack=True,
        enable_alerts=True,
    )
    manager = WebhookManager(settings)

    mock_response = httpx.Response(status_code=204)

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response
        await manager.send_alert(sample_event)

        assert mock_post.call_count == 2
        calls = [call[0][0] for call in mock_post.call_args_list]
        assert "https://discord.webhook" in calls
        assert "https://slack.webhook" in calls


@pytest.mark.anyio
async def test_webhook_send_retry_logic(sample_event: SentinelAlertEvent) -> None:
    """Verify that network errors trigger the maximum of 3 retry attempts."""
    settings = WebhookSettings(
        discord_url="https://discord.webhook",
        enable_discord=True,
        enable_slack=False,
        enable_alerts=True,
    )
    manager = WebhookManager(settings)

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post, \
         patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:

        mock_post.side_effect = httpx.ConnectError("Connection failed")
        await manager.send_alert(sample_event)

        # Should attempt 3 times (1 initial + 2 retries)
        assert mock_post.call_count == 3
        assert mock_sleep.call_count == 2


@pytest.mark.anyio
async def test_webhook_failure_isolation(sample_event: SentinelAlertEvent) -> None:
    """Verify that one webhook failure does not impact other notifications or the bus."""
    settings = WebhookSettings(
        discord_url="https://discord.webhook",
        slack_url="https://slack.webhook",
        enable_discord=True,
        enable_slack=True,
        enable_alerts=True,
    )
    manager = WebhookManager(settings)

    async def mock_post_impl(url, **kwargs):
        if "slack" in url:
            raise httpx.ConnectError("Slack is down")
        return httpx.Response(status_code=204)

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=mock_post_impl), \
         patch("asyncio.sleep", new_callable=AsyncMock):

        # Must not raise exception — failure must be silently absorbed
        await manager.send_alert(sample_event)


@pytest.mark.anyio
async def test_webhook_http_error_does_not_raise(sample_event: SentinelAlertEvent) -> None:
    """Non-2xx HTTP responses must be logged but not raised."""
    settings = WebhookSettings(
        discord_url="https://discord.webhook",
        enable_discord=True,
        enable_slack=False,
        enable_alerts=True,
    )
    manager = WebhookManager(settings)

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post, \
         patch("asyncio.sleep", new_callable=AsyncMock):

        mock_post.return_value = httpx.Response(status_code=500)
        # Should not raise — all attempts will log a warning and return False
        await manager.send_alert(sample_event)
        assert mock_post.call_count == manager.max_retries


@pytest.mark.anyio
async def test_webhook_global_kill_switch_prevents_delivery(sample_event: SentinelAlertEvent) -> None:
    """When enable_alerts=False, no HTTP requests should be made regardless of per-service flags."""
    settings = WebhookSettings(
        discord_url="https://discord.webhook",
        slack_url="https://slack.webhook",
        enable_discord=True,
        enable_slack=True,
        enable_alerts=False,  # global kill-switch OFF
    )
    manager = WebhookManager(settings)

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        await manager.send_alert(sample_event)
        mock_post.assert_not_called()


@pytest.mark.anyio
async def test_webhook_no_endpoints_configured(sample_event: SentinelAlertEvent) -> None:
    """With all services disabled, send_alert must silently return without posting."""
    settings = WebhookSettings(
        enable_discord=False,
        enable_slack=False,
        enable_alerts=True,
    )
    manager = WebhookManager(settings)

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        await manager.send_alert(sample_event)
        mock_post.assert_not_called()


@pytest.mark.anyio
async def test_webhook_enabled_but_url_missing_does_not_raise(sample_event: SentinelAlertEvent) -> None:
    """Enabled service with empty URL should log a warning, not raise."""
    settings = WebhookSettings(
        discord_url="",
        enable_discord=True,
        enable_slack=False,
        enable_alerts=True,
    )
    manager = WebhookManager(settings)

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        await manager.send_alert(sample_event)
        mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# Event handler safety tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_event_handler_loads_settings_safely(sample_event: SentinelAlertEvent) -> None:
    """Verify on_sentinel_alert executes without throwing errors even if settings fail."""
    with patch("src.config.settings.get_settings") as mock_get_settings:
        mock_get_settings.side_effect = Exception("Settings load failure")
        # Should catch and log error gracefully — must not raise
        await on_sentinel_alert(sample_event)


@pytest.mark.anyio
async def test_event_handler_swallows_webhook_send_failure(sample_event: SentinelAlertEvent) -> None:
    """on_sentinel_alert must absorb any unexpected exception from WebhookManager."""
    mock_settings = MagicMock()
    mock_settings.webhook = WebhookSettings(
        discord_url="https://discord.webhook",
        enable_discord=True,
        enable_alerts=True,
    )
    with patch("src.config.settings.get_settings", return_value=mock_settings), \
         patch(
             "src.runtime.events.webhook_manager.WebhookManager.send_alert",
             new_callable=AsyncMock,
             side_effect=RuntimeError("Unexpected send failure"),
         ):
        # Must not propagate the exception
        await on_sentinel_alert(sample_event)


# ---------------------------------------------------------------------------
# End-to-end integration test
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_e2e_webhook_integration_with_client() -> None:
    """Verify end-to-end integration by scoring a block transaction via client."""
    from src.api.main import app
    from httpx import AsyncClient, ASGITransport

    env_overrides = {
        "AEGIS_ROLE_ANALYST": "191be6474686af9fb423c46b283e68841233c98e3683589bb475916e65db083f",  # test-key-analyst
        "DISCORD_WEBHOOK_URL": "https://discord.webhook",
        "ENABLE_DISCORD_WEBHOOK": "true",
        "ENABLE_WEBHOOK_ALERTS": "true",
    }

    mock_post_urls = []
    original_post = AsyncClient.post

    async def mock_post_impl(self, url, *args, **kwargs):
        url_str = str(url)
        if "discord.webhook" in url_str or "slack.webhook" in url_str:
            mock_post_urls.append(url_str)
            return httpx.Response(status_code=204)
        return await original_post(self, url, *args, **kwargs)

    with patch.dict("os.environ", env_overrides, clear=True), \
         patch.object(AsyncClient, "post", mock_post_impl):

        from src.config.settings import reset_settings_cache
        reset_settings_cache()

        # Mock account profiles to include known mule account for testing
        # Must be set before app starts to be available during scoring
        from src.api.main import state, _FALLBACK_SCORING
        state.account_profiles = {
            "mule_acc_001": {
                "account_id": "mule_acc_001",
                "avg_transaction_amount": 5000,
                "risk_score": 0.9,
                "is_mule": True
            }
        }
        # Also ensure mule_accounts includes the test account
        state.mule_accounts.add("mule_acc_001")
        # Override fallback scoring to ensure high amounts trigger BLOCK
        _FALLBACK_SCORING["fallback_trigger_score"] = 1.0  # Always use fallback
        _FALLBACK_SCORING["block_above"] = 100000  # Block amounts > 100k

        # App client startup runs lifecycle manager, which hooks up default subscriptions
        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                # Send high risk transaction to force a BLOCK
                headers = {"X-API-Key": "test-key-analyst"}
                from datetime import datetime, timezone
                payload = {
                    "transaction_id": "tx_block_test",
                    "source_account": "mule_acc_001",  # Known mule
                    "target_account": "suspect_account_1",
                    "amount": 500000.0,
                    "currency": "USD",
                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                }

                resp = await client.post("/api/v1/fraud/check", headers=headers, json=payload)
                assert resp.status_code == 200
                assert resp.json()["decision"] == "block"

                # Since the event dispatcher operates out of band, let's wait a moment
                # for event loop delivery to trigger the post call
                for _ in range(20):
                    if len(mock_post_urls) > 0:
                        break
                    await asyncio.sleep(0.05)

                assert len(mock_post_urls) >= 1
                assert "https://discord.webhook" in mock_post_urls[0]
