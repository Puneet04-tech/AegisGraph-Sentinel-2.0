"""
External Integration Storage Engine.

Thread-safe storage for connections, webhooks, and integrations.
"""

from collections import OrderedDict
from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    Connection,
    Webhook,
    WebhookDelivery,
    APIEndpoint,
    ThirdPartyIntegration,
    OrchestratedWorkflow,
    IntegrationLog,
    IntegrationStatus,
)

logger = logging.getLogger(__name__)


class IntegrationStore:
    """Thread-safe storage for integration data.
    
    Provides:
        - O(1) lookup by ID
        - LRU cache for bounded memory
        - Thread-safe operations
        - Integration logging
    """
    
    def __init__(self, max_size: int = 5000):
        """Initialize the integration store."""
        self._max_size = max_size
        self._lock = Lock()
        
        # Connections
        self._connections: Dict[str, Connection] = {}
        
        # Webhooks
        self._webhooks: Dict[str, Webhook] = {}
        
        # Webhook deliveries
        self._deliveries: OrderedDict[str, WebhookDelivery] = OrderedDict()
        
        # API endpoints
        self._api_endpoints: Dict[str, APIEndpoint] = {}
        
        # Third-party integrations
        self._third_party: Dict[str, ThirdPartyIntegration] = {}
        
        # Orchestrated workflows
        self._workflows: Dict[str, OrchestratedWorkflow] = {}
        
        # Integration logs
        self._logs: OrderedDict[str, IntegrationLog] = OrderedDict()
        
        # Initialize default integrations
        self._initialize_defaults()
    
    def _initialize_defaults(self):
        """Initialize default third-party integrations."""
        integrations = [
            ThirdPartyIntegration(
                name="ThreatConnect",
                provider="threatconnect",
                endpoint="https://api.threatconnect.com",
                auth_type="API_KEY",
                features=["threat_intelligence", "indicator_lookup"],
                status=IntegrationStatus.INACTIVE,
            ),
            ThirdPartyIntegration(
                name="Recorded Future",
                provider="recordedfuture",
                endpoint="https://api.recordedfuture.com",
                auth_type="API_KEY",
                features=["risk_list", "alerting"],
                status=IntegrationStatus.INACTIVE,
            ),
            ThirdPartyIntegration(
                name="Splunk SIEM",
                provider="splunk",
                endpoint="https://localhost:8089",
                auth_type="BASIC",
                features=["log_ingestion", "search"],
                status=IntegrationStatus.INACTIVE,
            ),
        ]
        
        for integration in integrations:
            self._third_party[integration.integration_id] = integration
    
    # Connection Methods
    def store_connection(self, connection: Connection) -> Connection:
        """Store a connection."""
        with self._lock:
            self._connections[connection.connection_id] = connection
        return connection
    
    def get_connection(self, connection_id: str) -> Optional[Connection]:
        """Get connection by ID."""
        return self._connections.get(connection_id)
    
    def get_all_connections(self) -> List[Connection]:
        """Get all connections."""
        return list(self._connections.values())
    
    def get_active_connections(self) -> List[Connection]:
        """Get active connections."""
        return [c for c in self._connections.values() if c.status == IntegrationStatus.ACTIVE]
    
    def delete_connection(self, connection_id: str) -> bool:
        """Delete a connection."""
        with self._lock:
            if connection_id in self._connections:
                del self._connections[connection_id]
                return True
        return False
    
    # Webhook Methods
    def store_webhook(self, webhook: Webhook) -> Webhook:
        """Store a webhook."""
        with self._lock:
            self._webhooks[webhook.webhook_id] = webhook
        return webhook
    
    def get_webhook(self, webhook_id: str) -> Optional[Webhook]:
        """Get webhook by ID."""
        return self._webhooks.get(webhook_id)
    
    def get_all_webhooks(self) -> List[Webhook]:
        """Get all webhooks."""
        return list(self._webhooks.values())
    
    def get_enabled_webhooks(self) -> List[Webhook]:
        """Get enabled webhooks."""
        return [w for w in self._webhooks.values() if w.enabled]
    
    def delete_webhook(self, webhook_id: str) -> bool:
        """Delete a webhook."""
        with self._lock:
            if webhook_id in self._webhooks:
                del self._webhooks[webhook_id]
                return True
        return False
    
    # Webhook Delivery Methods
    def store_delivery(self, delivery: WebhookDelivery) -> WebhookDelivery:
        """Store webhook delivery."""
        with self._lock:
            self._deliveries[delivery.delivery_id] = delivery
            self._deliveries.move_to_end(delivery.delivery_id)
            
            while len(self._deliveries) > self._max_size:
                self._deliveries.popitem(last=False)
        
        return delivery
    
    def get_delivery(self, delivery_id: str) -> Optional[WebhookDelivery]:
        """Get delivery by ID."""
        return self._deliveries.get(delivery_id)
    
    def get_pending_deliveries(self) -> List[WebhookDelivery]:
        """Get pending deliveries."""
        return [d for d in self._deliveries.values() if d.status == "PENDING"]
    
    def get_recent_deliveries(self, limit: int = 100) -> List[WebhookDelivery]:
        """Get recent deliveries."""
        deliveries = list(self._deliveries.values())
        return sorted(deliveries, key=lambda d: d.created_at, reverse=True)[:limit]
    
    # API Endpoint Methods
    def store_api_endpoint(self, endpoint: APIEndpoint) -> APIEndpoint:
        """Store API endpoint."""
        with self._lock:
            self._api_endpoints[endpoint.endpoint_id] = endpoint
        return endpoint
    
    def get_api_endpoint(self, endpoint_id: str) -> Optional[APIEndpoint]:
        """Get API endpoint by ID."""
        return self._api_endpoints.get(endpoint_id)
    
    def get_all_api_endpoints(self) -> List[APIEndpoint]:
        """Get all API endpoints."""
        return list(self._api_endpoints.values())
    
    def get_enabled_api_endpoints(self) -> List[APIEndpoint]:
        """Get enabled API endpoints."""
        return [e for e in self._api_endpoints.values() if e.enabled]
    
    # Third-Party Integration Methods
    def store_third_party(self, integration: ThirdPartyIntegration) -> ThirdPartyIntegration:
        """Store third-party integration."""
        with self._lock:
            self._third_party[integration.integration_id] = integration
        return integration
    
    def get_third_party(self, integration_id: str) -> Optional[ThirdPartyIntegration]:
        """Get third-party integration by ID."""
        return self._third_party.get(integration_id)
    
    def get_all_third_party(self) -> List[ThirdPartyIntegration]:
        """Get all third-party integrations."""
        return list(self._third_party.values())
    
    def get_active_third_party(self) -> List[ThirdPartyIntegration]:
        """Get active third-party integrations."""
        return [i for i in self._third_party.values() if i.status == IntegrationStatus.ACTIVE]
    
    # Workflow Methods
    def store_workflow(self, workflow: OrchestratedWorkflow) -> OrchestratedWorkflow:
        """Store orchestrated workflow."""
        with self._lock:
            self._workflows[workflow.workflow_id] = workflow
        return workflow
    
    def get_workflow(self, workflow_id: str) -> Optional[OrchestratedWorkflow]:
        """Get workflow by ID."""
        return self._workflows.get(workflow_id)
    
    def get_all_workflows(self) -> List[OrchestratedWorkflow]:
        """Get all workflows."""
        return list(self._workflows.values())
    
    def get_enabled_workflows(self) -> List[OrchestratedWorkflow]:
        """Get enabled workflows."""
        return [w for w in self._workflows.values() if w.enabled]
    
    # Log Methods
    def store_log(self, log: IntegrationLog) -> IntegrationLog:
        """Store integration log."""
        with self._lock:
            self._logs[log.log_id] = log
            self._logs.move_to_end(log.log_id)
            
            while len(self._logs) > self._max_size:
                self._logs.popitem(last=False)
        
        return log
    
    def get_recent_logs(self, limit: int = 100) -> List[IntegrationLog]:
        """Get recent logs."""
        logs = list(self._logs.values())
        return sorted(logs, key=lambda l: l.created_at, reverse=True)[:limit]
    
    def get_logs_by_type(self, integration_type: str, limit: int = 100) -> List[IntegrationLog]:
        """Get logs by integration type."""
        logs = [l for l in self._logs.values() if l.integration_type == integration_type]
        return sorted(logs, key=lambda l: l.created_at, reverse=True)[:limit]
    
    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "connections_stored": len(self._connections),
            "active_connections": len(self.get_active_connections()),
            "webhooks_stored": len(self._webhooks),
            "enabled_webhooks": len(self.get_enabled_webhooks()),
            "deliveries_stored": len(self._deliveries),
            "pending_deliveries": len(self.get_pending_deliveries()),
            "api_endpoints_stored": len(self._api_endpoints),
            "third_party_stored": len(self._third_party),
            "active_third_party": len(self.get_active_third_party()),
            "workflows_stored": len(self._workflows),
            "logs_stored": len(self._logs),
        }


# Global singleton
_integration_store: Optional[IntegrationStore] = None


def get_integration_store() -> IntegrationStore:
    """Get or create the singleton integration store instance."""
    global _integration_store
    
    if _integration_store is None:
        _integration_store = IntegrationStore()
    return _integration_store