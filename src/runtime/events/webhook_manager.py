"""Real-time webhook notification manager for Sentinel alerts (Discord/Slack)."""

from __future__ import annotations

import asyncio
import httpx
from typing import Any, Dict

from ...observability import get_logger
from ...config.settings import WebhookSettings
from .event_types import SentinelAlertEvent

_logger = get_logger("runtime.events.webhooks")


class WebhookManager:
    """Formats and dispatches high-severity alert notifications to Discord and Slack."""

    def __init__(self, settings: WebhookSettings) -> None:
        self.settings = settings
        self.timeout = 5.0
        self.max_retries = 3

    def _format_discord_payload(self, event: SentinelAlertEvent) -> Dict[str, Any]:
        color = 16711680 if event.severity.upper() in ("HIGH", "CRITICAL") else 16768256  # Red or Gold
        
        fields = [
            {"name": "Severity", "value": event.severity, "inline": True},
            {"name": "Source", "value": event.source, "inline": True},
            {"name": "Transaction ID", "value": str(event.payload.get("transaction_id", "N/A")), "inline": True},
        ]
        
        if "amount" in event.payload:
            currency = event.payload.get("currency", "")
            fields.append({"name": "Amount", "value": f"{event.payload['amount']} {currency}".strip(), "inline": True})
            
        if "source_account" in event.payload:
            fields.append({"name": "Source Account", "value": str(event.payload["source_account"]), "inline": True})
            
        if "target_account" in event.payload:
            fields.append({"name": "Target Account", "value": str(event.payload["target_account"]), "inline": True})
            
        if "risk_score" in event.payload:
            fields.append({"name": "Risk Score", "value": f"{event.payload['risk_score']:.4f}", "inline": True})
            
        if "explanation" in event.payload:
            fields.append({"name": "Explanation", "value": str(event.payload["explanation"]), "inline": False})

        return {
            "username": "AegisGraph Sentinel",
            "embeds": [
                {
                    "title": f"🚨 {event.title}",
                    "description": event.message,
                    "color": color,
                    "fields": fields,
                    "timestamp": event.timestamp,
                }
            ],
        }

    def _format_slack_payload(self, event: SentinelAlertEvent) -> Dict[str, Any]:
        fields = [
            {"type": "mrkdwn", "text": f"*Severity:*\n`{event.severity}`"},
            {"type": "mrkdwn", "text": f"*Source:*\n`{event.source}`"},
        ]
        
        if "transaction_id" in event.payload:
            fields.append({"type": "mrkdwn", "text": f"*Transaction ID:*\n{event.payload['transaction_id']}"})
            
        if "amount" in event.payload:
            currency = event.payload.get("currency", "")
            fields.append({"type": "mrkdwn", "text": f"*Amount:*\n{event.payload['amount']} {currency}".strip()})
            
        if "source_account" in event.payload:
            fields.append({"type": "mrkdwn", "text": f"*Source Account:*\n{event.payload['source_account']}"})
            
        if "target_account" in event.payload:
            fields.append({"type": "mrkdwn", "text": f"*Target Account:*\n{event.payload['target_account']}"})
            
        if "risk_score" in event.payload:
            fields.append({"type": "mrkdwn", "text": f"*Risk Score:*\n{event.payload['risk_score']:.4f}"})

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Sentinel Alert: {event.title}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Message:* {event.message}",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": fields,
            },
        ]
        
        if "explanation" in event.payload:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Explanation:*\n{event.payload['explanation']}",
                },
            })
            
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Timestamp: {event.timestamp} | Event ID: {event.event_id}",
                }
            ],
        })

        return {
            "text": f"🚨 *Sentinel Alert*: {event.title} - {event.message}",
            "blocks": blocks,
        }

    async def _send_with_retry(self, client: httpx.AsyncClient, service_name: str, url: str, payload: dict) -> bool:
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = await client.post(url, json=payload, timeout=self.timeout)
                if resp.status_code in (200, 201, 204):
                    _logger.info(
                        f"Successfully sent alert to {service_name}",
                        event_type=f"webhook_{service_name.lower()}_success",
                        metadata={"attempt": attempt},
                    )
                    return True
                else:
                    _logger.warning(
                        f"Failed sending alert to {service_name}: HTTP {resp.status_code}",
                        event_type=f"webhook_{service_name.lower()}_http_error",
                        metadata={"status_code": resp.status_code, "attempt": attempt, "body": resp.text},
                    )
            except (httpx.HTTPError, asyncio.TimeoutError) as exc:
                _logger.warning(
                    f"Network error sending alert to {service_name}: {exc}",
                    event_type=f"webhook_{service_name.lower()}_network_error",
                    metadata={"error": str(exc), "attempt": attempt},
                )
            
            if attempt < self.max_retries:
                # Exponential backoff (1s, 2s)
                await asyncio.sleep(2 ** (attempt - 1))
                
        return False

    async def send_alert(self, event: SentinelAlertEvent) -> None:
        """Asynchronously dispatches formatted alert notifications to active webhook endpoints."""
        async with httpx.AsyncClient() as client:
            tasks = []
            
            if self.settings.enable_discord and self.settings.discord_url:
                payload = self._format_discord_payload(event)
                tasks.append(
                    self._send_with_retry(client, "Discord", self.settings.discord_url, payload)
                )
                
            if self.settings.enable_slack and self.settings.slack_url:
                payload = self._format_slack_payload(event)
                tasks.append(
                    self._send_with_retry(client, "Slack", self.settings.slack_url, payload)
                )

            if tasks:
                # Run Discord and Slack notifications concurrently with failure isolation
                await asyncio.gather(*tasks, return_exceptions=True)
