import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from src.config.loaders import load_settings
from src.config.schemas import WebhookSettings
from src.runtime.events.event_types import SentinelAlertEvent
from src.runtime.events.webhook_manager import WebhookManager

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

def test_teams_settings_defaults() -> None:
    with patch.dict("os.environ", {}, clear=True):
        settings = load_settings()
        assert settings.webhook.teams_url == ""
        assert settings.webhook.enable_teams is False

def test_teams_settings_env_loading() -> None:
    env_overrides = {
        "TEAMS_WEBHOOK_URL": "https://outlook.office.com/webhook/abc",
        "ENABLE_TEAMS_WEBHOOK": "true",
        "ENABLE_WEBHOOK_ALERTS": "true",
    }
    with patch.dict("os.environ", env_overrides, clear=True):
        settings = load_settings()
        assert settings.webhook.teams_url == "https://outlook.office.com/webhook/abc"
        assert settings.webhook.enable_teams is True

def test_teams_payload_formatting(sample_event) -> None:
    settings = WebhookSettings(
        teams_url="https://outlook.office.com/webhook/abc",
        enable_teams=True,
        enable_alerts=True
    )
    manager = WebhookManager(settings)
    payload = manager._format_teams_payload(sample_event)
    assert payload["@type"] == "MessageCard"
    assert payload["summary"] == "Sentinel Alert: Transaction Blocked"
    assert len(payload["sections"]) == 1
    section = payload["sections"][0]
    assert section["activityTitle"] == "🚨 Transaction Blocked"
    assert section["activitySubtitle"] == "A high-risk transaction was detected."
    
    facts = {f["name"]: f["value"] for f in section["facts"]}
    assert facts["Severity"] == "`HIGH`"
    assert facts["Transaction ID"] == "tx_9999"
    assert facts["Amount"] == "250000.0 USD"
    assert facts["Risk Score"] == "0.9500"

@pytest.mark.asyncio
async def test_teams_send_success(sample_event) -> None:
    settings = WebhookSettings(
        teams_url="https://outlook.office.com/webhook/abc",
        enable_teams=True,
        enable_alerts=True
    )
    manager = WebhookManager(settings)
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        await manager.send_alert(sample_event)
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://outlook.office.com/webhook/abc"
        assert kwargs["json"]["@type"] == "MessageCard"
