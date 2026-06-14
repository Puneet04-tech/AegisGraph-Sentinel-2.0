"""Audit trail logging for fraud decisions and security events."""

import threading
from threading import Lock
from typing import Any, Dict, List, Optional

from .structured_logger import StructuredLogger, get_logger


class AuditLogger:
    """Domain-specific audit events built on structured JSON logging."""

    def __init__(self, module: str = "audit") -> None:
        self._logger: StructuredLogger = get_logger(module)

    def log_fraud_decision(
        self,
        *,
        transaction_id: str,
        decision: str,
        risk_score: float,
        triggered_modules: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload = {
            "transaction_id": transaction_id,
            "decision": decision,
            "risk_score": risk_score,
            "triggered_modules": triggered_modules or [],
            **(metadata or {}),
        }
        self._logger.audit(
            "Fraud decision recorded",
            event_type="fraud_decision",
            metadata=payload,
        )

    def log_security_action(
        self,
        action: str,
        *,
        actor: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload = {"action": action, "actor": actor, **(metadata or {})}
        self._logger.audit(
            f"Security action: {action}",
            event_type="security_action",
            metadata=payload,
        )

    def log_exception_trace(
        self,
        *,
        exc_type: str,
        message: str,
        status_code: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload = {
            "exc_type": exc_type,
            "status_code": status_code,
            **(metadata or {}),
        }
        self._logger.audit(
            message,
            event_type="exception_trace",
            metadata=payload,
        )

    def log_admin_action(self, action: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        self.log_security_action(action, metadata={"scope": "admin", **(metadata or {})})


_audit_logger: Optional[AuditLogger] = None
_audit_logger_lock = Lock()


def get_audit_logger() -> AuditLogger:
    global _audit_logger
    with _audit_logger_lock:
        if _audit_logger is None:
            _audit_logger = AuditLogger()
        return _audit_logger
