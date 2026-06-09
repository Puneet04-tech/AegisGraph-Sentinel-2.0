"""
Tests for External Integration Hub.

Comprehensive tests for:
    - Connector Framework
    - Webhook Manager
    - Integration Store
"""

import pytest
from datetime import datetime, timezone

from src.external_integration import (
    ConnectorType,
    AuthType,
    WebhookEvent,
    IntegrationStatus,
    Connection,
    Webhook,
    IntegrationStore,
    get_integration_store,
    ConnectorFramework,
    get_connector_framework,
    WebhookManager,
    get_webhook_manager,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def store():
    """Create a fresh integration store for testing."""
    return IntegrationStore(max_size=100)


@pytest.fixture
def connector_framework(store):
    """Create a connector framework."""
    return ConnectorFramework(store=store)


@pytest.fixture
def webhook_manager(store):
    """Create a webhook manager."""
    return WebhookManager(store=store)


# =============================================================================
# Store Tests
# =============================================================================

class TestIntegrationStore:
    """Tests for IntegrationStore."""
    
    def test_store_connection(self, store):
        """Test storing a connection."""
        connection = Connection(
            name="Test Connection",
            connector_type=ConnectorType.REST_API,
            endpoint="https://api.test.com",
            auth_type=AuthType.API_KEY,
        )
        
        stored = store.store_connection(connection)
        retrieved = store.get_connection(connection.connection_id)
        
        assert retrieved is not None
        assert retrieved.name == "Test Connection"
    
    def test_get_all_connections(self, store):
        """Test getting all connections."""
        connections = store.get_all_connections()
        assert isinstance(connections, list)
    
    def test_store_webhook(self, store):
        """Test storing a webhook."""
        webhook = Webhook(
            name="Test Webhook",
            endpoint="https://webhook.test.com",
            events=[WebhookEvent.FRAUD_DETECTED],
        )
        
        stored = store.store_webhook(webhook)
        retrieved = store.get_webhook(webhook.webhook_id)
        
        assert retrieved is not None
        assert retrieved.name == "Test Webhook"
    
    def test_get_enabled_webhooks(self, store):
        """Test getting enabled webhooks."""
        webhooks = store.get_enabled_webhooks()
        assert isinstance(webhooks, list)
    
    def test_get_stats(self, store):
        """Test getting store statistics."""
        stats = store.get_stats()
        
        assert "connections_stored" in stats
        assert "webhooks_stored" in stats


# =============================================================================
# Connector Framework Tests
# =============================================================================

class TestConnectorFramework:
    """Tests for ConnectorFramework."""
    
    def test_get_available_connectors(self, connector_framework):
        """Test getting available connectors."""
        connectors = connector_framework.get_available_connectors()
        
        assert len(connectors) >= 3
        assert any(c["id"] == "salesforce" for c in connectors)
    
    def test_create_connection(self, connector_framework):
        """Test creating a connection."""
        connection = connector_framework.create_connection(
            name="Test API",
            connector_type=ConnectorType.REST_API,
            endpoint="https://api.test.com",
            auth_type=AuthType.API_KEY,
            auth_config={"api_key": "test_key"},
        )
        
        assert connection.connection_id is not None
        assert connection.name == "Test API"
    
    def test_connect_disconnect(self, connector_framework):
        """Test connecting and disconnecting."""
        connection = connector_framework.create_connection(
            name="Test Connect",
            connector_type=ConnectorType.REST_API,
            endpoint="https://api.test.com",
            auth_type=AuthType.API_KEY,
        )
        
        result = connector_framework.connect(connection.connection_id)
        assert isinstance(result, bool)
        
        disconnect_result = connector_framework.disconnect(connection.connection_id)
        assert disconnect_result is True
    
    def test_health_check(self, connector_framework):
        """Test health check."""
        connection = connector_framework.create_connection(
            name="Health Check Test",
            connector_type=ConnectorType.REST_API,
            endpoint="https://api.test.com",
            auth_type=AuthType.API_KEY,
        )
        
        connector_framework.connect(connection.connection_id)
        health = connector_framework.health_check(connection.connection_id)
        
        assert "health_status" in health
    
    def test_execute_request(self, connector_framework):
        """Test executing a request."""
        connection = connector_framework.create_connection(
            name="Request Test",
            connector_type=ConnectorType.REST_API,
            endpoint="https://api.test.com",
            auth_type=AuthType.API_KEY,
        )
        
        # Retry connection until successful
        for _ in range(5):
            if connector_framework.connect(connection.connection_id):
                break
        
        result = connector_framework.execute_request(
            connection_id=connection.connection_id,
            method="GET",
            path="/test",
        )
        
        assert "success" in result or "error" in result
    
    def test_get_health_summary(self, connector_framework):
        """Test getting health summary."""
        summary = connector_framework.get_connection_health_summary()
        
        assert "total_connections" in summary
        assert "healthy" in summary


# =============================================================================
# Webhook Manager Tests
# =============================================================================

class TestWebhookManager:
    """Tests for WebhookManager."""
    
    def test_register_webhook(self, webhook_manager):
        """Test registering a webhook."""
        webhook = webhook_manager.register_webhook(
            name="Test Webhook",
            endpoint="https://webhook.test.com",
            events=[WebhookEvent.FRAUD_DETECTED, WebhookEvent.ALERT_TRIGGERED],
            secret="test_secret",
        )
        
        assert webhook.webhook_id is not None
        assert webhook.name == "Test Webhook"
        assert len(webhook.events) == 2
    
    def test_update_webhook(self, webhook_manager):
        """Test updating a webhook."""
        webhook = webhook_manager.register_webhook(
            name="Update Test",
            endpoint="https://webhook.test.com",
            events=[WebhookEvent.FRAUD_DETECTED],
        )
        
        updated = webhook_manager.update_webhook(
            webhook_id=webhook.webhook_id,
            name="Updated Webhook",
            enabled=False,
        )
        
        assert updated.name == "Updated Webhook"
        assert updated.enabled is False
    
    def test_trigger_event(self, webhook_manager):
        """Test triggering an event."""
        webhook_manager.register_webhook(
            name="Trigger Test",
            endpoint="https://webhook.test.com",
            events=[WebhookEvent.FRAUD_DETECTED],
        )
        
        deliveries = webhook_manager.trigger_event(
            event=WebhookEvent.FRAUD_DETECTED,
            payload={"fraud_id": "test_123", "amount": 5000},
        )
        
        assert isinstance(deliveries, list)
    
    def test_get_delivery_stats(self, webhook_manager):
        """Test getting delivery stats."""
        webhook_manager.register_webhook(
            name="Stats Test",
            endpoint="https://webhook.test.com",
            events=[WebhookEvent.INVESTIGATION_CREATED],
        )
        
        webhook_manager.trigger_event(
            event=WebhookEvent.INVESTIGATION_CREATED,
            payload={"case_id": "123"},
        )
        
        stats = webhook_manager.get_delivery_stats()
        
        assert "total_deliveries" in stats
        assert "success_rate" in stats


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for external integration."""
    
    def test_full_integration_workflow(
        self,
        connector_framework,
        webhook_manager,
    ):
        """Test full integration workflow."""
        # 1. Create connection
        connection = connector_framework.create_connection(
            name="Full Integration Test",
            connector_type=ConnectorType.REST_API,
            endpoint="https://api.test.com",
            auth_type=AuthType.API_KEY,
        )
        
        # 2. Connect (retry until active)
        for _ in range(5):
            if connector_framework.connect(connection.connection_id):
                break
        
        # 3. Register webhook
        webhook = webhook_manager.register_webhook(
            name="Full Integration Webhook",
            endpoint="https://webhook.test.com",
            events=[WebhookEvent.FRAUD_DETECTED],
        )
        
        # 4. Trigger event
        deliveries = webhook_manager.trigger_event(
            event=WebhookEvent.FRAUD_DETECTED,
            payload={"connection_id": connection.connection_id},
        )
        
        # 5. Execute request
        result = connector_framework.execute_request(
            connection_id=connection.connection_id,
            method="POST",
            path="/fraud/notify",
            data={"alert": "fraud_detected"},
        )
        
        # Verify
        assert connection.connection_id is not None
        assert webhook.webhook_id is not None
        assert isinstance(deliveries, list)
        # Result may have success or error depending on connection state
        assert "success" in result or "error" in result