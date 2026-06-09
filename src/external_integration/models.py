"""
External Integration Hub Models.

Data models for connectors, webhooks, API gateway, and integrations.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class ConnectorType(str, Enum):
    """Connector types."""
    REST_API = "REST_API"
    GRAPHQL = "GRAPHQL"
    WEBHOOK = "WEBHOOK"
    DATABASE = "DATABASE"
    FILE_BASED = "FILE_BASED"


class AuthType(str, Enum):
    """Authentication types."""
    API_KEY = "API_KEY"
    OAUTH2 = "OAUTH2"
    BASIC = "BASIC"
    BEARER = "BEARER"
    NONE = "NONE"


class WebhookEvent(str, Enum):
    """Webhook event types."""
    FRAUD_DETECTED = "FRAUD_DETECTED"
    ALERT_TRIGGERED = "ALERT_TRIGGERED"
    INVESTIGATION_CREATED = "INVESTIGATION_CREATED"
    CASE_ESCALATED = "CASE_ESCALATED"
    RISK_THRESHOLD_BREACHED = "RISK_THRESHOLD_BREACHED"


class IntegrationStatus(str, Enum):
    """Integration status."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    ERROR = "ERROR"
    PENDING = "PENDING"


class Connection(BaseModel):
    """External system connection."""
    connection_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    connector_type: ConnectorType
    endpoint: str
    auth_type: AuthType
    auth_config: Dict[str, Any] = Field(default_factory=dict)
    status: IntegrationStatus = IntegrationStatus.PENDING
    last_health_check: Optional[datetime] = None
    health_status: str = "UNKNOWN"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Webhook(BaseModel):
    """Webhook registration."""
    webhook_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    endpoint: str
    events: List[WebhookEvent] = Field(default_factory=list)
    secret: Optional[str] = None
    enabled: bool = True
    retry_count: int = 3
    retry_delay_seconds: int = 60
    timeout_seconds: int = 30
    headers: Dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WebhookDelivery(BaseModel):
    """Webhook delivery record."""
    delivery_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    webhook_id: str
    event: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    status: str  # PENDING, DELIVERED, FAILED
    attempts: int = 0
    last_attempt: Optional[datetime] = None
    response_code: Optional[int] = None
    response_body: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class APIEndpoint(BaseModel):
    """Exposed API endpoint configuration."""
    endpoint_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    path: str
    method: str
    description: str
    rate_limit: int = 100  # requests per minute
    rate_limit_window: int = 60  # seconds
    auth_required: bool = True
    transformation: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThirdPartyIntegration(BaseModel):
    """Third-party integration configuration."""
    integration_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    provider: str  # ThreatConnect, Recorded Future, etc.
    endpoint: str
    auth_type: AuthType
    auth_config: Dict[str, Any] = Field(default_factory=dict)
    features: List[str] = Field(default_factory=list)  # enrichment, lookup, etc.
    status: IntegrationStatus = IntegrationStatus.PENDING
    last_sync: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OrchestratedWorkflow(BaseModel):
    """Integration workflow orchestration."""
    workflow_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    trigger_event: str
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    error_handling: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    last_triggered: Optional[datetime] = None
    execution_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IntegrationLog(BaseModel):
    """Integration activity log."""
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    integration_type: str
    action: str
    entity_id: Optional[str] = None
    status: str
    details: Dict[str, Any] = Field(default_factory=dict)
    duration_ms: Optional[float] = None
    error_message: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))