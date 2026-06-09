"""
External Integration Hub.

A production-grade integration module for connecting AegisGraph Sentinel
with external systems, providing webhook management, API gateway, and
third-party integrations.

Modules:
    - Connector Framework: External system connections
    - Webhook Manager: Event-driven integrations
"""

from .models import (
    ConnectorType,
    AuthType,
    WebhookEvent,
    IntegrationStatus,
    Connection,
    Webhook,
    WebhookDelivery,
    APIEndpoint,
    ThirdPartyIntegration,
    OrchestratedWorkflow,
    IntegrationLog,
)
from .store import IntegrationStore, get_integration_store
from .connector_framework import ConnectorFramework, get_connector_framework
from .webhook_manager import WebhookManager, get_webhook_manager

__all__ = [
    # Enums
    "ConnectorType",
    "AuthType",
    "WebhookEvent",
    "IntegrationStatus",
    # Models
    "Connection",
    "Webhook",
    "WebhookDelivery",
    "APIEndpoint",
    "ThirdPartyIntegration",
    "OrchestratedWorkflow",
    "IntegrationLog",
    # Store
    "IntegrationStore",
    "get_integration_store",
    # Modules
    "ConnectorFramework",
    "get_connector_framework",
    "WebhookManager",
    "get_webhook_manager",
]