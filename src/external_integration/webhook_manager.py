"""
Webhook Manager Module.

Provides webhook registration, event triggering, and delivery management.
"""

import hashlib
import hmac
import json
from typing import Callable, Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    Webhook,
    WebhookDelivery,
    WebhookEvent,
    IntegrationLog,
)
from .store import IntegrationStore, get_integration_store

logger = logging.getLogger(__name__)


class WebhookManager:
    """Webhook Manager for event-driven integrations.
    
    Provides:
        - Webhook registration
        - Event triggering
        - Delivery management
        - Retry logic
    """

    #: HTTP status codes at or above this are treated as a failed delivery.
    ERROR_STATUS_FLOOR = 400

    #: Response body kept on the delivery record, in characters. Enough to
    #: diagnose a rejection without storing an unbounded payload.
    RESPONSE_BODY_LIMIT = 2000

    #: Header carrying the HMAC-SHA256 signature of the request body, so a
    #: receiver can verify the payload came from us.
    SIGNATURE_HEADER = "X-AegisGraph-Signature"

    def __init__(
        self,
        store: Optional[IntegrationStore] = None,
        transport: Optional[Callable[..., Any]] = None,
    ):
        """Initialize the webhook manager.

        Args:
            store: Optional integration store
            transport: Callable performing the HTTP POST, matching
                ``requests.post``. Injectable so delivery can be exercised
                without reaching the network.
        """
        self._store = store or get_integration_store()
        self._transport = transport
        self._module_id = "webhook_manager"

    def _post(self, url: str, **kwargs: Any) -> Any:
        """Perform the HTTP POST, importing requests lazily."""
        if self._transport is not None:
            return self._transport(url, **kwargs)

        import requests

        return requests.post(url, **kwargs)
    
    def register_webhook(
        self,
        name: str,
        endpoint: str,
        events: List[WebhookEvent],
        secret: str = None,
        retry_count: int = 3,
        headers: Dict[str, str] = None,
    ) -> Webhook:
        """Register a new webhook."""
        logger.info(f"Registering webhook: {name}")
        
        webhook = Webhook(
            name=name,
            endpoint=endpoint,
            events=events,
            secret=secret,
            retry_count=retry_count,
            headers=headers or {},
        )
        
        self._store.store_webhook(webhook)
        self._log_action("webhook", "register", webhook.webhook_id, "SUCCESS")
        
        return webhook
    
    def update_webhook(
        self,
        webhook_id: str,
        name: str = None,
        endpoint: str = None,
        events: List[WebhookEvent] = None,
        enabled: bool = None,
    ) -> Webhook:
        """Update a webhook."""
        webhook = self._store.get_webhook(webhook_id)
        if not webhook:
            raise ValueError(f"Webhook {webhook_id} not found")
        
        if name:
            webhook.name = name
        if endpoint:
            webhook.endpoint = endpoint
        if events:
            webhook.events = events
        if enabled is not None:
            webhook.enabled = enabled
        
        self._store.store_webhook(webhook)
        return webhook
    
    def trigger_event(
        self,
        event: WebhookEvent,
        payload: Dict[str, Any],
    ) -> List[WebhookDelivery]:
        """Trigger webhook deliveries for an event."""
        logger.info(f"Triggering event: {event.value}")
        
        # Find matching webhooks
        webhooks = self._store.get_enabled_webhooks()
        matching = [w for w in webhooks if event in w.events]
        
        deliveries = []
        for webhook in matching:
            delivery = self._deliver_webhook(webhook, event, payload)
            deliveries.append(delivery)
        
        return deliveries
    
    def _deliver_webhook(
        self,
        webhook: Webhook,
        event: WebhookEvent,
        payload: Dict[str, Any],
    ) -> WebhookDelivery:
        """Deliver webhook payload."""
        delivery = WebhookDelivery(
            webhook_id=webhook.webhook_id,
            event=event.value,
            payload=payload,
            status="PENDING",
        )
        
        self._store.store_delivery(delivery)

        delivery.attempts = 1
        self._attempt_delivery(webhook, delivery)

        self._log_action(
            "webhook_delivery", "deliver", delivery.delivery_id,
            "SUCCESS" if delivery.status == "DELIVERED" else "FAILED",
        )

        self._store.store_delivery(delivery)
        return delivery

    def _attempt_delivery(self, webhook: Webhook, delivery: WebhookDelivery) -> bool:
        """POST the payload to the webhook endpoint and record the outcome.

        Delivery used to be ``random.random() > 0.1``: nothing was ever sent,
        and the recorded status, response code and the success rate derived
        from them described a coin flip rather than the endpoint.

        Never raises -- a transport failure is a failed delivery, not an error
        propagated into the caller's event trigger.
        """
        delivery.last_attempt = datetime.now(timezone.utc)
        body = json.dumps(delivery.payload, default=str)

        try:
            response = self._post(
                webhook.endpoint,
                data=body,
                headers=self._build_headers(webhook, body),
                timeout=webhook.timeout_seconds,
            )
        except Exception as exc:
            # The endpoint was unreachable, refused the connection or timed
            # out. There is no status code to record.
            logger.warning(
                "Webhook delivery to %s failed: %s", webhook.endpoint, exc,
            )
            delivery.status = "FAILED"
            delivery.response_code = None
            delivery.response_body = str(exc)[:self.RESPONSE_BODY_LIMIT]
            return False

        delivery.response_code = getattr(response, "status_code", None)
        delivery.response_body = str(
            getattr(response, "text", "") or ""
        )[:self.RESPONSE_BODY_LIMIT]

        delivered = (
            delivery.response_code is not None
            and delivery.response_code < self.ERROR_STATUS_FLOOR
        )
        delivery.status = "DELIVERED" if delivered else "FAILED"
        return delivered

    def _build_headers(self, webhook: Webhook, body: str) -> Dict[str, str]:
        """Headers for a delivery, including the payload signature.

        The webhook secret was stored and never used, so a receiver had no way
        to tell a genuine delivery from a forged one.
        """
        headers = {
            "Content-Type": "application/json",
            **webhook.headers,
        }

        if webhook.secret:
            signature = hmac.new(
                webhook.secret.encode("utf-8"),
                body.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            headers[self.SIGNATURE_HEADER] = f"sha256={signature}"

        return headers
    
    def retry_delivery(self, delivery_id: str) -> bool:
        """Retry a failed webhook delivery."""
        delivery = self._store.get_delivery(delivery_id)
        if not delivery:
            return False
        
        webhook = self._store.get_webhook(delivery.webhook_id)
        if not webhook or not webhook.enabled:
            return False
        
        if delivery.attempts >= webhook.retry_count:
            # The retry budget is already spent; retrying again would let a
            # caller loop past the configured limit.
            logger.info(
                "Delivery %s has exhausted its %d retries",
                delivery_id, webhook.retry_count,
            )
            self._log_action("webhook_retry", "retry", delivery_id, "EXHAUSTED")
            return False

        logger.info(f"Retrying delivery: {delivery_id}")

        delivery.attempts += 1

        # A retry re-sends the payload. It used to be a second coin flip, with
        # better odds -- so a retry could "succeed" against an endpoint that
        # was never contacted.
        if self._attempt_delivery(webhook, delivery):
            self._log_action("webhook_retry", "retry", delivery_id, "SUCCESS")
        else:
            if delivery.attempts >= webhook.retry_count:
                self._log_action("webhook_retry", "retry", delivery_id, "EXHAUSTED")
            else:
                self._log_action("webhook_retry", "retry", delivery_id, "FAILED")
        
        self._store.store_delivery(delivery)
        return delivery.status == "DELIVERED"
    
    def get_webhook_deliveries(self, webhook_id: str) -> List[WebhookDelivery]:
        """Get deliveries for a webhook."""
        deliveries = self._store.get_recent_deliveries(limit=1000)
        return [d for d in deliveries if d.webhook_id == webhook_id]
    
    def get_delivery_stats(self) -> Dict[str, Any]:
        """Get delivery statistics."""
        deliveries = self._store.get_recent_deliveries(limit=10000)
        
        total = len(deliveries)
        delivered = sum(1 for d in deliveries if d.status == "DELIVERED")
        failed = sum(1 for d in deliveries if d.status == "FAILED")
        pending = sum(1 for d in deliveries if d.status == "PENDING")
        
        return {
            "total_deliveries": total,
            "delivered": delivered,
            "failed": failed,
            "pending": pending,
            "success_rate": (delivered / total * 100) if total > 0 else 0,
        }
    
    def _log_action(
        self,
        integration_type: str,
        action: str,
        entity_id: str,
        status: str,
    ):
        """Log integration action."""
        log = IntegrationLog(
            integration_type=integration_type,
            action=action,
            entity_id=entity_id,
            status=status,
        )
        self._store.store_log(log)


# Global singleton
_webhook_manager: Optional[WebhookManager] = None


def get_webhook_manager(store: Optional[IntegrationStore] = None) -> WebhookManager:
    """Get or create the singleton WebhookManager instance."""
    global _webhook_manager
    
    if _webhook_manager is None:
        _webhook_manager = WebhookManager(store=store)
    return _webhook_manager