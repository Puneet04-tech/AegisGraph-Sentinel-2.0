"""Unit and integration tests for the Real-Time Webhook Integration (Issue #633)."""

from __future__ import annotations

import asyncio
import pytest
import httpx
from unittest.mock import AsyncMock, patch

from src.config.loaders import load_settings
from src.config.schemas import WebhookSettings
from src.runtime.events.event_types import SentinelAlertEvent
from src.runtime.events.webhook_manager import WebhookManager
from src.runtime.events.event_handlers import on_sentinel_alert


@pytest.fixture
def sample_event() -> SentinelAlertEvent:
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


def test_webhook_settings_defaults() -> None:
    """Verify default values are correctly loaded when no env vars are defined."""
    # Temporarily clear environment variables
    with patch.dict("os.environ", {}, clear=True):
        settings = load_settings()
        assert settings.webhook.discord_url == ""
        assert settings.webhook.slack_url == ""
        assert settings.webhook.enable_discord is False
        assert settings.webhook.enable_slack is False


def test_webhook_settings_env_loading() -> None:
    """Verify configuration loads properly from environment variables."""
    env_overrides = {
        "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/123",
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/abc",
        "ENABLE_DISCORD_WEBHOOK": "true",
        "ENABLE_SLACK_WEBHOOK": "1",
    }
    with patch.dict("os.environ", env_overrides, clear=True):
        settings = load_settings()
        assert settings.webhook.discord_url == "https://discord.com/api/webhooks/123"
        assert settings.webhook.slack_url == "https://hooks.slack.com/services/abc"
        assert settings.webhook.enable_discord is True
        assert settings.webhook.enable_slack is True


def test_discord_payload_formatting(sample_event: SentinelAlertEvent) -> None:
    """Verify Discord payload follows the required structure and contains transaction info."""
    settings = WebhookSettings(discord_url="http://test", enable_discord=True)
    manager = WebhookManager(settings)
    
    payload = manager._format_discord_payload(sample_event)
    
    assert payload["username"] == "AegisGraph Sentinel"
    assert len(payload["embeds"]) == 1
    embed = payload["embeds"][0]
    assert embed["title"] == "🚨 Transaction Blocked"
    assert embed["description"] == "A high-risk transaction was detected."
    assert embed["color"] == 16711680  # HIGH severity color
    
    fields = {f["name"]: f["value"] for f in embed["fields"]}
    assert fields["Severity"] == "HIGH"
    assert fields["Transaction ID"] == "tx_9999"
    assert fields["Amount"] == "250000.0 USD"
    assert fields["Risk Score"] == "0.9500"
    assert fields["Explanation"] == "High velocity and suspected mule link."


def test_slack_payload_formatting(sample_event: SentinelAlertEvent) -> None:
    """Verify Slack payload matches the Slack Block Kit specification."""
    settings = WebhookSettings(slack_url="http://test", enable_slack=True)
    manager = WebhookManager(settings)
    
    payload = manager._format_slack_payload(sample_event)
    
    assert "blocks" in payload
    blocks = payload["blocks"]
    assert blocks[0]["type"] == "header"
    assert "Transaction Blocked" in blocks[0]["text"]["text"]
    
    section_text = blocks[1]["text"]["text"]
    assert "A high-risk transaction was detected." in section_text
    
    fields = [f["text"] for f in blocks[3]["fields"]]
    assert any("tx_9999" in text for text in fields)
    assert any("250000.0 USD" in text for text in fields)
    assert any("0.9500" in text for text in fields)
    
    assert "High velocity and suspected mule link." in blocks[4]["text"]["text"]


@pytest.mark.anyio
async def test_webhook_send_success(sample_event: SentinelAlertEvent) -> None:
    """Verify successful dispatch routes to both endpoints when enabled."""
    settings = WebhookSettings(
        discord_url="https://discord.webhook",
        slack_url="https://slack.webhook",
        enable_discord=True,
        enable_slack=True,
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
    )
    manager = WebhookManager(settings)
    
    async def mock_post_impl(url, **kwargs):
        if "slack" in url:
            raise httpx.ConnectError("Slack is down")
        return httpx.Response(status_code=204)
        
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=mock_post_impl), \
         patch("asyncio.sleep", new_callable=AsyncMock):
        
        # Must not raise exception
        await manager.send_alert(sample_event)


@pytest.mark.anyio
async def test_event_handler_loads_settings_safely(sample_event: SentinelAlertEvent) -> None:
    """Verify on_sentinel_alert executes without throwing errors even if settings fail."""
    with patch("src.config.settings.get_settings") as mock_get_settings:
        mock_get_settings.side_effect = Exception("Settings load failure")
        # Should catch and log error gracefully
        await on_sentinel_alert(sample_event)


@pytest.mark.anyio
async def test_e2e_webhook_integration_with_client() -> None:
    """Verify end-to-end integration by scoring a block transaction via client."""
    from src.api.main import app
    from httpx import AsyncClient, ASGITransport
    
    env_overrides = {
        "AEGIS_ROLE_ANALYST": "191be6474686af9fb423c46b283e68841233c98e3683589bb475916e65db083f",  # test-key-analyst
        "DISCORD_WEBHOOK_URL": "https://discord.webhook",
        "ENABLE_DISCORD_WEBHOOK": "true",
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



