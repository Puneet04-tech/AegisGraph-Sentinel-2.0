"""
Observability & Platform Health Dashboard.

A production-grade observability module for unified monitoring,
alerting, and health visibility across all AegisGraph Sentinel components.

Includes:
    - Structured Logging: Request context and structured JSON logs
    - Audit Logging: Fraud decisions and security events
    - Metrics Logging: Performance metrics collection
    - Health Monitor: Component health tracking
    - Performance Metrics: Performance tracking
    - Alert Manager: Alert handling
    - Dashboard: Platform dashboard
"""

# Original logging/audit functionality
from .audit_logger import AuditLogger, get_audit_logger
from .metrics_logger import MetricsLogger
from .structured_logger import (
    StructuredLogger,
    clear_request_context,
    generate_request_id,
    get_correlation_id,
    get_logger,
    get_request_id,
    set_request_context,
)

# New observability functionality
from .models import (
    ComponentStatus,
    AlertSeverity,
    AlertStatus,
    ComponentHealth,
    PerformanceMetric,
    AlertRule,
    Alert,
    AuditEntry,
    DashboardSnapshot,
    Incident,
)
from .store import ObservabilityStore, get_observability_store
from .health_monitor import HealthMonitor, get_health_monitor
from .performance_metrics import PerformanceTracker, get_performance_tracker
from .alert_manager import AlertManager, get_alert_manager
from .dashboard import PlatformDashboard, get_platform_dashboard

__all__ = [
    # Original exports
    "AuditLogger",
    "AuditLogger",
    "MetricsLogger",
    "StructuredLogger",
    "clear_request_context",
    "generate_request_id",
    "get_audit_logger",
    "get_correlation_id",
    "get_logger",
    "get_request_id",
    "set_request_context",
    # New exports
    # Enums
    "ComponentStatus",
    "AlertSeverity",
    "AlertStatus",
    # Models
    "ComponentHealth",
    "PerformanceMetric",
    "AlertRule",
    "Alert",
    "AuditEntry",
    "DashboardSnapshot",
    "Incident",
    # Store
    "ObservabilityStore",
    "get_observability_store",
    # Modules
    "HealthMonitor",
    "get_health_monitor",
    "PerformanceTracker",
    "get_performance_tracker",
    "AlertManager",
    "get_alert_manager",
    "PlatformDashboard",
    "get_platform_dashboard",
]