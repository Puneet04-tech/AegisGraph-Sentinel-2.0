"""
Connector Framework Module.

Provides connector management, connection pooling, and health monitoring.
"""

import base64
import time
from typing import Callable, Dict, List, Optional, Any
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
    
    #: HTTP status codes at or above this are treated as a failure.
    ERROR_STATUS_FLOOR = 400

    #: Timeout applied to connection probes and requests, in seconds.
    REQUEST_TIMEOUT_SECONDS = 30

    #: Response body kept on a result, in characters.
    RESPONSE_BODY_LIMIT = 2000

    def __init__(
        self,
        store: Optional[IntegrationStore] = None,
        transport: Optional[Callable[..., Any]] = None,
    ):
        """Initialize the connector framework.

        Args:
            store: Optional integration store
            transport: Callable performing the HTTP request, matching
                ``requests.request(method, url, **kwargs)``. Injectable so
                connections can be exercised without reaching the network.
        """
        self._store = store or get_integration_store()
        self._transport = transport
        self._module_id = "connector_framework"

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        """Perform an HTTP request, importing requests lazily."""
        if self._transport is not None:
            return self._transport(method, url, **kwargs)

        import requests

        return requests.request(method, url, **kwargs)

    def _probe(self, connection: Connection) -> tuple:
        """Contact a connection's endpoint.

        Returns ``(reachable, latency_ms, error)``. Never raises: an
        unreachable endpoint is an unhealthy connection, not an exception.
        """
        started = time.monotonic()
        try:
            response = self._request(
                "GET",
                connection.endpoint,
                headers=self._auth_headers(connection),
                timeout=self.REQUEST_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            logger.warning(
                "Probe of %s (%s) failed: %s",
                connection.name, connection.endpoint, exc,
            )
            return False, round((time.monotonic() - started) * 1000, 2), str(exc)

        latency_ms = round((time.monotonic() - started) * 1000, 2)
        status_code = getattr(response, "status_code", None)

        if status_code is None or status_code >= self.ERROR_STATUS_FLOOR:
            return False, latency_ms, f"HTTP {status_code}"

        return True, latency_ms, None

    def _auth_headers(self, connection: Connection) -> Dict[str, str]:
        """Build authentication headers from the connection's auth config.

        auth_config was stored and never used by any request, so credentials a
        caller supplied were silently ignored.
        """
        config = connection.auth_config or {}
        headers: Dict[str, str] = {}

        if connection.auth_type == AuthType.API_KEY:
            api_key = config.get("api_key")
            if api_key:
                headers[config.get("header", "X-API-Key")] = str(api_key)
        elif connection.auth_type in (AuthType.BEARER, AuthType.OAUTH2):
            token = config.get("token") or config.get("access_token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif connection.auth_type == AuthType.BASIC:
            username = config.get("username", "")
            password = config.get("password", "")
            if username or password:
                encoded = base64.b64encode(
                    f"{username}:{password}".encode("utf-8")
                ).decode("ascii")
                headers["Authorization"] = f"Basic {encoded}"

        return headers

    def _response_body(self, response: Any) -> Any:
        """Best-effort decode of a response body."""
        try:
            return response.json()
        except Exception:
            return str(getattr(response, "text", "") or "")[:self.RESPONSE_BODY_LIMIT]

    
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
        """Establish connection to external system.

        Connecting used to be ``random.random() > 0.1``: the endpoint was
        never contacted, so a connection to a host that does not exist came up
        ACTIVE and HEALTHY nine times out of ten.
        """
        connection = self._store.get_connection(connection_id)
        if not connection:
            return False

        logger.info(f"Connecting to {connection.name}")

        success, _, error = self._probe(connection)

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
            self._log_action(
                "connection", "connect", connection_id, "FAILED",
                error_message=error or "Connection failed",
            )
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

        # The health check used to be a 95% coin flip that never contacted the
        # endpoint, so health_percentage in the summary below described the
        # coin rather than any external system.
        is_healthy, latency_ms, error = self._probe(connection)

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
            "latency_ms": latency_ms,
            "error": error,
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

        # The request was never sent: success was random.random() > 0.05 and
        # the reported duration_ms was random.uniform(10, 500), so callers
        # were shown latency figures for calls that never happened.
        url = f"{connection.endpoint.rstrip('/')}/{path.lstrip('/')}"
        started = time.monotonic()

        try:
            response = self._request(
                method,
                url,
                headers=self._auth_headers(connection),
                json=data,
                timeout=self.REQUEST_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            duration = (time.monotonic() - started) * 1000
            logger.warning("Request to %s failed: %s", url, exc)
            self._log_action(
                "request", f"{method}_{path}", connection_id, "FAILED",
                duration_ms=duration, error_message=str(exc),
            )
            return {
                "success": False,
                "status_code": None,
                "error": str(exc),
                "duration_ms": duration,
            }

        duration = (time.monotonic() - started) * 1000
        status_code = getattr(response, "status_code", None)
        success = status_code is not None and status_code < self.ERROR_STATUS_FLOOR

        self._log_action(
            "request", f"{method}_{path}", connection_id,
            "SUCCESS" if success else "FAILED",
            duration_ms=duration,
            error_message=None if success else f"HTTP {status_code}",
        )

        return {
            "success": success,
            "status_code": status_code,
            "data": self._response_body(response),
            "duration_ms": duration,
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