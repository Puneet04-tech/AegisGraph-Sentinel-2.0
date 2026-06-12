"""
Credential Exposure Monitor.

Monitors credential exposures and data breaches.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import CredentialExposure
from .store import DRPStore, get_drp_store


class CredentialMonitor:
    """Engine for credential exposure monitoring."""

    def __init__(self, store: Optional[DRPStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_drp_store()
        self._employee_emails: set = set()

    def register_employee_email(self, email: str) -> None:
        """Register an employee email for monitoring."""
        self._employee_emails.add(email.lower())

    def register_employee_domain(self, domain: str) -> None:
        """Register an employee email domain."""
        pass

    def add_exposure(
        self,
        email: str,
        source: str,
        breach_date: Optional[datetime] = None,
        password_hash: Optional[str] = None,
    ) -> CredentialExposure:
        """Add a credential exposure."""
        exposure = CredentialExposure(
            exposure_id=f"cred-{uuid.uuid4().hex[:12]}",
            email=email,
            source=source,
            breach_date=breach_date or datetime.now(timezone.utc),
            password_hash=password_hash,
            affected_employees=1 if email.lower() in self._employee_emails else 0,
        )
        
        self.store.add_credential_exposure(exposure)
        
        self.store.log_audit(
            user_id="system",
            action="credential_exposure_detected",
            resource_type="credential_exposure",
            resource_id=exposure.exposure_id,
            details={"email": email, "source": source},
        )
        
        return exposure

    def get_exposures(
        self,
        include_employee_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Get credential exposures."""
        exposures = self.store.get_credential_exposures()
        
        if include_employee_only:
            exposures = [
                e for e in exposures
                if e.email.lower() in self._employee_emails
            ]
        
        return [
            {
                "exposure_id": e.exposure_id,
                "email": e.email,
                "source": e.source,
                "breach_date": e.breach_date.isoformat() if e.breach_date else None,
                "status": e.status,
                "is_employee": e.email.lower() in self._employee_emails,
            }
            for e in exposures
        ]

    def get_employee_exposure_count(self) -> int:
        """Get count of exposed employee credentials."""
        exposures = self.store.get_credential_exposures()
        return sum(1 for e in exposures if e.email.lower() in self._employee_emails)


# Singleton instance
_engine: Optional[CredentialMonitor] = None


def get_credential_monitor() -> CredentialMonitor:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = CredentialMonitor()
    return _engine


def reset_credential_monitor() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None