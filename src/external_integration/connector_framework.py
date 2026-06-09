"""
Connector Framework Module.

Provides connector management, connection pooling, and health monitoring.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    Connection,
    ConnectorType,
    AuthType,
    IntegrationStatus,
    IntegrationLog,
)
from .store import IntegrationStore, get_integration_store

logger = logging.getLogger(__name__)


class ConnectorFramework:
    """Connector Framework for external system integration.
    
    Provides:
        - Pre-built connectors
        - Custom connector creation
        - Connection pooling
        - Health monitoring
    """
    
    def __init__(self, store: Optional[IntegrationStore] = None):
        """Initialize the connector framework."""
        self._store = store or get_integration_store()
        self._module_id = "connector_framework"
    
    def get_available_connectors(self) -> List[Dict[str, Any]]:
        """Get list of available pre-built connectors."""
        return [
            {
                "id": "salesforce",
                "name": "Salesforce",
                "type": "CRM",
                "connector_type": ConnectorType.REST_API.value,
                "auth_types": [AuthType.OAUTH2.value],
                "features": ["case_sync", "account_lookup"],
            },
            {
                "id": "servicenow",
                "name": "ServiceNow",
                "type": "ITSM",
                "connector_type": ConnectorType.REST_API.value,
                "auth_types": [AuthType.API_KEY.value, AuthType.BASIC.value],
                "features": ["incident_sync", "ticket_creation"],
            },
            {
                "id": "splunk",
                "name": "Splunk SIEM",
                "type": "SIEM",
                "connector_type": ConnectorType.REST_API.value,
                "auth_types": [AuthType.BASIC.value],
                "features": ["log_ingestion", "search"],
            },
            {
                "id": "threatconnect",
                "name": "ThreatConnect",
                "type": "Threat Intelligence",
                "connector_type": ConnectorType.REST_API.value,
                "auth_types": [AuthType.API_KEY.value],
                "features": ["threat_lookup", "indicator_enrichment"],
            },
            {
                "id": "recorded_future",
                "name": "Recorded Future",
                "type": "Threat Intelligence",
                "connector_type": ConnectorType.REST_API.value,
                "auth_types": [AuthType.API_KEY.value],
                "features": ["risk_list", "alerting"],
            },
        ]
    
    def create_connection(
        self,
        name: str,
        connector_type: ConnectorType,
        endpoint: str,
        auth_type: AuthType,
        auth_config: Dict[str, Any] = None,
    ) -> Connection:
        """Create a new external connection."""
        logger.info(f"Creating connection: {name}")
        
        connection = Connection(
            name=name,
            connector_type=connector_type,
            endpoint=endpoint,
            auth_type=auth_type,
            auth_config=auth_config or {},
            status=IntegrationStatus.PENDING,
        )
        
        self._store.store_connection(connection)
        self._log_action("connection", "create", connection.connection_id, "SUCCESS")
        
        return connection
    
    def connect(self, connection_id: str) -> bool:
        """Establish connection to external system."""
        connection = self._store.get_connection(connection_id)
        if not connection:
            return False
        
        logger.info(f"Connecting to {connection.name}")
        
        # Simulate connection attempt
        success = random.random() > 0.1  # 90% success rate
        
        if success:
            connection.status = IntegrationStatus.ACTIVE
            connection.health_status = "HEALTHY"
            connection.last_health_check = datetime.now(timezone.utc)
            self._store.store_connection(connection)
            self._log_action("connection", "connect", connection_id, "SUCCESS")
            return True
        else:
            connection.status = IntegrationStatus.ERROR
            connection.health_status = "UNHEALTHY"
            self._store.store_connection(connection)
            self._log_action("connection", "connect", connection_id, "FAILED", error_message="Connection failed")
            return False
    
    def disconnect(self, connection_id: str) -> bool:
        """Disconnect from external system."""
        connection = self._store.get_connection(connection_id)
        if not connection:
            return False
        
        logger.info(f"Disconnecting from {connection.name}")
        
        connection.status = IntegrationStatus.INACTIVE
        connection.health_status = "DISCONNECTED"
        self._store.store_connection(connection)
        self._log_action("connection", "disconnect", connection_id, "SUCCESS")
        
        return True
    
    def health_check(self, connection_id: str) -> Dict[str, Any]:
        """Perform health check on connection."""
        connection = self._store.get_connection(connection_id)
        if not connection:
            return {"error": "Connection not found"}
        
        logger.info(f"Health check for {connection.name}")
        
        # Simulate health check
        is_healthy = random.random() > 0.05  # 95% healthy
        
        connection.last_health_check = datetime.now(timezone.utc)
        connection.health_status = "HEALTHY" if is_healthy else "UNHEALTHY"
        
        if connection.status == IntegrationStatus.ACTIVE and not is_healthy:
            connection.status = IntegrationStatus.ERROR
        
        self._store.store_connection(connection)
        
        return {
            "connection_id": connection_id,
            "name": connection.name,
            "status": connection.status.value,
            "health_status": connection.health_status,
            "last_check": connection.last_health_check.isoformat(),
        }
    
    def execute_request(
        self,
        connection_id: str,
        method: str,
        path: str,
        data: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Execute request through connection."""
        connection = self._store.get_connection(connection_id)
        if not connection:
            return {"error": "Connection not found"}
        
        if connection.status != IntegrationStatus.ACTIVE:
            return {"error": "Connection not active"}
        
        logger.info(f"Executing {method} {path} on {connection.name}")
        
        # Simulate request execution
        success = random.random() > 0.05
        duration = random.uniform(10, 500)
        
        if success:
            self._log_action("request", f"{method}_{path}", connection_id, "SUCCESS", duration_ms=duration)
            return {
                "success": True,
                "status_code": 200,
                "data": {"result": "success", "duration_ms": duration},
            }
        else:
            self._log_action("request", f"{method}_{path}", connection_id, "FAILED", duration_ms=duration, error_message="Request failed")
            return {
                "success": False,
                "status_code": 500,
                "error": "Request failed",
            }
    
    def get_connection_health_summary(self) -> Dict[str, Any]:
        """Get overall connection health summary."""
        connections = self._store.get_all_connections()
        
        healthy = sum(1 for c in connections if c.health_status == "HEALTHY")
        unhealthy = sum(1 for c in connections if c.health_status == "UNHEALTHY")
        unknown = sum(1 for c in connections if c.health_status == "UNKNOWN")
        
        return {
            "total_connections": len(connections),
            "active_connections": len([c for c in connections if c.status == IntegrationStatus.ACTIVE]),
            "healthy": healthy,
            "unhealthy": unhealthy,
            "unknown": unknown,
            "health_percentage": (healthy / len(connections) * 100) if connections else 0,
        }
    
    def _log_action(
        self,
        integration_type: str,
        action: str,
        entity_id: str,
        status: str,
        duration_ms: float = None,
        error_message: str = None,
    ):
        """Log integration action."""
        log = IntegrationLog(
            integration_type=integration_type,
            action=action,
            entity_id=entity_id,
            status=status,
            duration_ms=duration_ms,
            error_message=error_message,
        )
        self._store.store_log(log)


# Global singleton
_connector_framework: Optional[ConnectorFramework] = None


def get_connector_framework(store: Optional[IntegrationStore] = None) -> ConnectorFramework:
    """Get or create the singleton ConnectorFramework instance."""
    global _connector_framework
    
    if _connector_framework is None:
        _connector_framework = ConnectorFramework(store=store)
    return _connector_framework