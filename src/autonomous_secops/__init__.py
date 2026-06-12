"""
Autonomous AI Security Operations Platform.

Enterprise platform for autonomous security operations center
capable of monitoring, investigating, correlating, prioritizing,
and responding to threats without analyst intervention.
"""

from .models import (
    # Enums
    AlertStatus,
    IncidentStatus,
    PlaybookStatus,
    Severity,
    # Data Classes
    Alert,
    AuditEvent,
    CorrelationRule,
    Incident,
    Playbook,
    PlaybookExecution,
    SOCMetrics,
    ThreatHunt,
)

from .store import (
    AutonomousSecOpsStore,
    get_secops_store,
    reset_secops_store,
)

from .secops_engine import (
    SecurityOperationsEngine,
    get_secops_engine,
    reset_secops_engine,
)

from .correlation_engine import (
    ThreatCorrelationEngine,
    get_correlation_engine,
    reset_correlation_engine,
)

from .investigation_engine import (
    InvestigationEngine,
    get_investigation_engine,
    reset_investigation_engine,
)

from .playbook_engine import (
    PlaybookEngine,
    get_playbook_engine,
    reset_playbook_engine,
)

from .threat_hunting import (
    ThreatHuntingEngine,
    get_threat_hunting_engine,
    reset_threat_hunting_engine,
)

from .service import (
    AutonomousSecOpsService,
    get_secops_service,
    reset_secops_service,
)

__all__ = [
    # Enums
    "AlertStatus",
    "IncidentStatus",
    "PlaybookStatus",
    "Severity",
    # Models
    "Alert",
    "AuditEvent",
    "CorrelationRule",
    "Incident",
    "Playbook",
    "PlaybookExecution",
    "SOCMetrics",
    "ThreatHunt",
    # Store
    "AutonomousSecOpsStore",
    "get_secops_store",
    "reset_secops_store",
    # Engines
    "SecurityOperationsEngine",
    "get_secops_engine",
    "reset_secops_engine",
    "ThreatCorrelationEngine",
    "get_correlation_engine",
    "reset_correlation_engine",
    "InvestigationEngine",
    "get_investigation_engine",
    "reset_investigation_engine",
    "PlaybookEngine",
    "get_playbook_engine",
    "reset_playbook_engine",
    "ThreatHuntingEngine",
    "get_threat_hunting_engine",
    "reset_threat_hunting_engine",
    # Service
    "AutonomousSecOpsService",
    "get_secops_service",
    "reset_secops_service",
]