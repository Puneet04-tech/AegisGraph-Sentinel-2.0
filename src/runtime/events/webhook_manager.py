"""Real-time webhook notification manager for Sentinel alerts (Discord/Slack).

Issue #633 — Enhancement: Real-Time Webhook Integration for Sentinel Alerts.

This module provides a production-ready ``WebhookManager`` service that:

* Receives ``SentinelAlertEvent`` objects from the runtime event bus.
* Formats rich Discord embed payloads and structured Slack Block Kit messages.
* Delivers notifications concurrently to all configured endpoints.
* Retries transient failures with exponential back-off (up to ``max_retries``).
* Isolates per-service failures so one broken endpoint never blocks others.
* Logs all outcomes — successes, HTTP errors, and network errors — without
  raising exceptions to the caller.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import httpx

from ...observability import get_logger
from ...config.settings import WebhookSettings
from .event_types import SentinelAlertEvent

_logger = get_logger("runtime.events.webhooks")

# Discord embed colour codes (24-bit RGB as decimal)
_COLOUR_CRITICAL = 16711680  # #FF0000 — red, used for HIGH / CRITICAL severity
_COLOUR_HIGH = 16744272     # #FF7010 — orange-red
_COLOUR_MEDIUM = 16768256   # #FFCC00 — gold / yellow
_COLOUR_LOW = 3329330       # #33CC12 — green

_SEVERITY_COLOURS: Dict[str, int] = {
    "CRITICAL": _COLOUR_CRITICAL,
    "HIGH": _COLOUR_CRITICAL,
    "MEDIUM": _COLOUR_MEDIUM,
    "LOW": _COLOUR_LOW,
}


def _discord_colour(severity: str) -> int:
    """Return the Discord embed colour integer for the given *severity* label."""
    return _SEVERITY_COLOURS.get(severity.upper(), _COLOUR_HIGH)


class WebhookManager:
    """Format and dispatch high-severity Sentinel alert notifications to Discord and Slack.

    Parameters
    ----------
    settings:
        A :class:`~src.config.schemas.WebhookSettings` instance that carries
        the configured webhook URLs and per-service enable flags.
    timeout:
        HTTP request timeout in seconds (default: 5.0).
    max_retries:
        Maximum number of POST attempts per endpoint before giving up
        (default: 3).  Retries use exponential back-off: 1 s, 2 s, …

    Usage
    -----
    Instantiate once per alert (or share an instance) and call
    :meth:`send_alert` from within an async event handler::

        manager = WebhookManager(settings.webhook)
        await manager.send_alert(event)
    """

    def __init__(
        self,
        settings: WebhookSettings,
        *,
        timeout: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        self.settings = settings
        self.timeout = timeout
        self.max_retries = max_retries

    # ------------------------------------------------------------------
    # Payload formatters
    # ------------------------------------------------------------------

    def _format_discord_payload(self, event: SentinelAlertEvent) -> Dict[str, Any]:
        """Build a Discord webhook payload with a rich embed card.

        The embed includes:

        * A coloured header reflecting the alert severity.
        * Inline fields for severity, source, and transaction identifier.
        * Optional inline fields for amount, currency, account IDs, and risk score.
        * A full-width field for the human-readable explanation when present.
        * An ISO-8601 timestamp used by Discord to display local time in the client.

        Parameters
        ----------
        event:
            The :class:`~src.runtime.events.event_types.SentinelAlertEvent`
            to format.

        Returns
        -------
        dict
            A JSON-serialisable dict ready for ``POST``-ing to a Discord
            webhook URL.
        """
        colour = _discord_colour(event.severity)

        fields: List[Dict[str, Any]] = [
            {"name": "Severity", "value": f"`{event.severity}`", "inline": True},
            {"name": "Source", "value": f"`{event.source}`", "inline": True},
            {
                "name": "Transaction ID",
                "value": str(event.payload.get("transaction_id", "N/A")),
                "inline": True,
            },
        ]

        amount = event.payload.get("amount")
        if amount is not None:
            currency = event.payload.get("currency", "")
            fields.append(
                {
                    "name": "Amount",
                    "value": f"{amount} {currency}".strip(),
                    "inline": True,
                }
            )

        if "source_account" in event.payload:
            fields.append(
                {
                    "name": "Source Account",
                    "value": str(event.payload["source_account"]),
                    "inline": True,
                }
            )

        if "target_account" in event.payload:
            fields.append(
                {
                    "name": "Target Account",
                    "value": str(event.payload["target_account"]),
                    "inline": True,
                }
            )

        risk_score = event.payload.get("risk_score")
        if risk_score is not None:
            fields.append(
                {
                    "name": "Risk Score",
                    "value": f"{risk_score:.4f}",
                    "inline": True,
                }
            )

        explanation = event.payload.get("explanation")
        if explanation:
            fields.append(
                {
                    "name": "Explanation",
                    "value": str(explanation),
                    "inline": False,
                }
            )

        return {
            "username": "AegisGraph Sentinel",
            "embeds": [
                {
                    "title": f"🚨 {event.title}",
                    "description": event.message,
                    "color": colour,
                    "fields": fields,
                    "timestamp": event.timestamp,
                    "footer": {
                        "text": f"Event ID: {event.event_id}",
                    },
                }
            ],
        }

    def _format_slack_payload(self, event: SentinelAlertEvent) -> Dict[str, Any]:
        """Build a Slack webhook payload using Block Kit structured layout.

        The message contains:

        * A ``header`` block with the alert title.
        * A ``section`` block with the human-readable message.
        * A ``divider`` for visual separation.
        * A ``section`` with up to 10 ``mrkdwn`` field pairs (severity, source,
          transaction ID, amount, account IDs, risk score).
        * An optional ``section`` for the explanation text.
        * A ``context`` block showing the ISO-8601 timestamp and event ID.

        Parameters
        ----------
        event:
            The :class:`~src.runtime.events.event_types.SentinelAlertEvent`
            to format.

        Returns
        -------
        dict
            A JSON-serialisable dict ready for ``POST``-ing to a Slack
            incoming-webhook URL.
        """
        fields: List[Dict[str, str]] = [
            {"type": "mrkdwn", "text": f"*Severity:*\n`{event.severity}`"},
            {"type": "mrkdwn", "text": f"*Source:*\n`{event.source}`"},
        ]

        if "transaction_id" in event.payload:
            fields.append(
                {
                    "type": "mrkdwn",
                    "text": f"*Transaction ID:*\n{event.payload['transaction_id']}",
                }
            )

        amount = event.payload.get("amount")
        if amount is not None:
            currency = event.payload.get("currency", "")
            fields.append(
                {
                    "type": "mrkdwn",
                    "text": f"*Amount:*\n{amount} {currency}".strip(),
                }
            )

        if "source_account" in event.payload:
            fields.append(
                {
                    "type": "mrkdwn",
                    "text": f"*Source Account:*\n{event.payload['source_account']}",
                }
            )

        if "target_account" in event.payload:
            fields.append(
                {
                    "type": "mrkdwn",
                    "text": f"*Target Account:*\n{event.payload['target_account']}",
                }
            )

        risk_score = event.payload.get("risk_score")
        if risk_score is not None:
            fields.append(
                {
                    "type": "mrkdwn",
                    "text": f"*Risk Score:*\n{risk_score:.4f}",
                }
            )

        # Slack Block Kit section blocks accept at most 10 fields
        fields = fields[:10]

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Sentinel Alert: {event.title}",
                    "emoji": True,
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

        explanation = event.payload.get("explanation")
        if explanation:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Explanation:*\n{explanation}",
                    },
                }
            )

        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"Timestamp: {event.timestamp} "
                            f"| Event ID: `{event.event_id}`"
                        ),
                    }
                ],
            }
        )

        return {
            "text": f"🚨 *Sentinel Alert*: {event.title} — {event.message}",
            "blocks": blocks,
        }

    # ------------------------------------------------------------------
    # HTTP delivery with retry / back-off
    # ------------------------------------------------------------------

    async def _send_with_retry(
        self,
        client: httpx.AsyncClient,
        service_name: str,
        url: str,
        payload: Dict[str, Any],
    ) -> bool:
        """POST *payload* to *url* with up to :attr:`max_retries` attempts.

        Retry strategy
        --------------
        * Attempt 1 is made immediately.
        * On failure (HTTP error or network exception) subsequent attempts
          are separated by ``2 ** (attempt - 1)`` seconds (1 s, 2 s, …).
        * Any non-2xx HTTP response is treated as a failure and logged at
          WARNING level.
        * Network errors (``httpx.HTTPError``) are logged at WARNING level
          and retried up to the maximum.
        * All failures are non-fatal — the method returns ``False`` without
          raising after exhausting retries.

        Parameters
        ----------
        client:
            A shared :class:`httpx.AsyncClient` that the caller owns.
        service_name:
            Human-readable label used in log messages (e.g. ``"Discord"``).
        url:
            The full webhook endpoint URL.
        payload:
            JSON-serialisable dict to deliver.

        Returns
        -------
        bool
            ``True`` on the first successful delivery, ``False`` if all
            retries are exhausted.
        """
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = await client.post(url, json=payload, timeout=self.timeout)
                if resp.status_code in (200, 201, 204):
                    _logger.info(
                        f"Webhook notification delivered to {service_name} "
                        f"(attempt {attempt}/{self.max_retries})",
                        event_type=f"webhook_{service_name.lower()}_success",
                        metadata={"attempt": attempt, "status_code": resp.status_code},
                    )
                    return True

                _logger.warning(
                    f"Webhook delivery to {service_name} returned HTTP "
                    f"{resp.status_code} (attempt {attempt}/{self.max_retries})",
                    event_type=f"webhook_{service_name.lower()}_http_error",
                    metadata={
                        "status_code": resp.status_code,
                        "attempt": attempt,
                        "response_body": resp.text[:512],
                    },
                )

            except (httpx.HTTPError, asyncio.TimeoutError) as exc:
                _logger.warning(
                    f"Network error delivering webhook to {service_name}: {exc} "
                    f"(attempt {attempt}/{self.max_retries})",
                    event_type=f"webhook_{service_name.lower()}_network_error",
                    metadata={"error": str(exc), "attempt": attempt},
                )

            if attempt < self.max_retries:
                backoff = 2 ** (attempt - 1)  # 1 s, 2 s, …
                await asyncio.sleep(backoff)

        _logger.error(
            f"All {self.max_retries} webhook delivery attempts to {service_name} failed. "
            "Giving up — alert will not be delivered to this endpoint.",
            event_type=f"webhook_{service_name.lower()}_exhausted",
            metadata={"max_retries": self.max_retries, "url": url},
        )
        return False

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def send_alert(self, event: SentinelAlertEvent) -> None:
        """Dispatch formatted alert notifications to all configured webhook endpoints.

        Both Discord and Slack requests are launched concurrently using
        :func:`asyncio.gather` with ``return_exceptions=True`` so that a
        failure in one notification path never blocks or cancels the other.

        The method is a no-op when:

        * ``settings.enable_alerts`` is ``False`` (global kill-switch), or
        * Neither ``enable_discord`` nor ``enable_slack`` is ``True``, or
        * A service is enabled but its URL is empty / not configured.

        Parameters
        ----------
        event:
            A :class:`~src.runtime.events.event_types.SentinelAlertEvent`
            representing the high-severity security alert to notify about.
        """
        # Global kill-switch: respect ENABLE_WEBHOOK_ALERTS
        if not getattr(self.settings, "enable_alerts", True):
            _logger.info(
                "Webhook alerts are globally disabled (ENABLE_WEBHOOK_ALERTS=false). "
                "Skipping notification.",
                event_type="webhook_globally_disabled",
                metadata={"event_id": event.event_id},
            )
            return

        async with httpx.AsyncClient() as client:
            tasks = []

            if self.settings.enable_discord and self.settings.discord_url:
                discord_payload = self._format_discord_payload(event)
                tasks.append(
                    self._send_with_retry(
                        client, "Discord", self.settings.discord_url, discord_payload
                    )
                )
            elif self.settings.enable_discord and not self.settings.discord_url:
                _logger.warning(
                    "Discord webhook is enabled but DISCORD_WEBHOOK_URL is not set. "
                    "Skipping Discord notification.",
                    event_type="webhook_discord_url_missing",
                )

            if self.settings.enable_slack and self.settings.slack_url:
                slack_payload = self._format_slack_payload(event)
                tasks.append(
                    self._send_with_retry(
                        client, "Slack", self.settings.slack_url, slack_payload
                    )
                )
            elif self.settings.enable_slack and not self.settings.slack_url:
                _logger.warning(
                    "Slack webhook is enabled but SLACK_WEBHOOK_URL is not set. "
                    "Skipping Slack notification.",
                    event_type="webhook_slack_url_missing",
                )

            if not tasks:
                _logger.info(
                    "No webhook endpoints are configured or enabled — "
                    "skipping notification for event %s.",
                    event_type="webhook_no_endpoints",
                    metadata={"event_id": event.event_id, "title": event.title},
                )
                return

            # Run all deliveries concurrently; exceptions are captured via
            # return_exceptions=True and logged by _send_with_retry.
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    _logger.error(
                        f"Unexpected exception during webhook delivery: {result}",
                        event_type="webhook_unexpected_error",
                        metadata={"error": str(result)},
                    )

