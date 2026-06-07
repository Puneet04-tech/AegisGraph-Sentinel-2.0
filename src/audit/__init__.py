"""In-memory audit trail primitives."""

from .audit_event import AuditEvent
from .audit_logger import AuditLogger, default_audit_logger, log_audit_event
from .audit_store import AuditStore, default_audit_store
from .correlation import generate_correlation_id, get_correlation_id
from .integrity import compute_hash, verify_chain

__all__ = [
    "AuditEvent",
    "AuditLogger",
    "AuditStore",
    "compute_hash",
    "default_audit_logger",
    "default_audit_store",
    "generate_correlation_id",
    "get_correlation_id",
    "log_audit_event",
    "verify_chain",
]
