"""
Webhook Manager Module.

Provides webhook registration, event triggering, and delivery management.
"""

import random
from typing import Dict, List, Optional, Any
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
    
    def __init__(self, store: Optional[IntegrationStore] = None):
        """Initialize the webhook manager."""
        self._store = store or get_integration_store()
        self._module_id = "webhook_manager"
    
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
        
        # Simulate delivery
        success = random.random() > 0.1
        delivery.attempts = 1
        delivery.last_attempt = datetime.now(timezone.utc)
        
        if success:
            delivery.status = "DELIVERED"
            delivery.response_code = 200
            self._log_action("webhook_delivery", "deliver", delivery.delivery_id, "SUCCESS")
        else:
            delivery.status = "FAILED"
            delivery.response_code = 500
            self._log_action("webhook_delivery", "deliver", delivery.delivery_id, "FAILED")
        
        self._store.store_delivery(delivery)
        return delivery
    
    def retry_delivery(self, delivery_id: str) -> bool:
        """Retry a failed webhook delivery."""
        delivery = self._store.get_delivery(delivery_id)
        if not delivery:
            return False
        
        webhook = self._store.get_webhook(delivery.webhook_id)
        if not webhook or not webhook.enabled:
            return False
        
        logger.info(f"Retrying delivery: {delivery_id}")
        
        delivery.attempts += 1
        delivery.last_attempt = datetime.now(timezone.utc)
        
        # Simulate retry
        success = random.random() > 0.3  # Better chance on retry
        
        if success:
            delivery.status = "DELIVERED"
            delivery.response_code = 200
            self._log_action("webhook_retry", "retry", delivery_id, "SUCCESS")
        else:
            delivery.status = "FAILED"
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