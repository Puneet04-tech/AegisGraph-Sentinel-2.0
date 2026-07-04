import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.runtime.events.event_types import SentinelAlertEvent
from src.runtime.events.event_handlers import on_sentinel_alert
from src.config.settings import RuntimeSettings
from src.config.schemas import ScoringSettings, WebhookSettings

@pytest.fixture
def make_event():
    def _make(amount: float, severity: str = "MEDIUM") -> SentinelAlertEvent:
        return SentinelAlertEvent(
            source="test_routing",
            severity=severity,
            title="Transaction Alert",
            message="Suspicious transaction flow.",
            payload={"amount": amount, "transaction_id": "tx_123"},
        )
    return _make

@pytest.mark.asyncio
async def test_no_escalation_below_threshold(make_event) -> None:
    event = make_event(100.0) # $100
    
    mock_settings = MagicMock(spec=RuntimeSettings)
    mock_settings.scoring = MagicMock(spec=ScoringSettings)
    mock_settings.scoring.high_value_threshold = 1000.0
    mock_settings.webhook = MagicMock(spec=WebhookSettings)
    
    with patch("src.config.settings.get_settings", return_value=mock_settings), \
         patch("src.runtime.events.webhook_manager.WebhookManager.send_alert", new_callable=AsyncMock) as mock_send:
        await on_sentinel_alert(event)
        mock_send.assert_called_once_with(event)
        assert event.severity == "MEDIUM"
        assert "Escalated" not in event.title

@pytest.mark.asyncio
async def test_escalation_above_threshold(make_event) -> None:
    event = make_event(2000.0) # $2000 > $1000
    
    mock_settings = MagicMock(spec=RuntimeSettings)
    mock_settings.scoring = MagicMock(spec=ScoringSettings)
    mock_settings.scoring.high_value_threshold = 1000.0
    mock_settings.webhook = MagicMock(spec=WebhookSettings)
    
    with patch("src.config.settings.get_settings", return_value=mock_settings), \
         patch("src.runtime.events.webhook_manager.WebhookManager.send_alert", new_callable=AsyncMock) as mock_send:
        await on_sentinel_alert(event)
        mock_send.assert_called_once_with(event)
        assert event.severity == "HIGH"
        assert event.title == "[Escalated] Transaction Alert"

@pytest.mark.asyncio
async def test_no_escalation_if_already_high(make_event) -> None:
    event = make_event(2000.0, severity="CRITICAL")
    
    mock_settings = MagicMock(spec=RuntimeSettings)
    mock_settings.scoring = MagicMock(spec=ScoringSettings)
    mock_settings.scoring.high_value_threshold = 1000.0
    mock_settings.webhook = MagicMock(spec=WebhookSettings)
    
    with patch("src.config.settings.get_settings", return_value=mock_settings), \
         patch("src.runtime.events.webhook_manager.WebhookManager.send_alert", new_callable=AsyncMock) as mock_send:
        await on_sentinel_alert(event)
        mock_send.assert_called_once_with(event)
        assert event.severity == "CRITICAL"
        assert "Escalated" not in event.title
