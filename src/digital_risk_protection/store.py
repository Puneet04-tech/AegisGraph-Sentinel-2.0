"""
Digital Risk Protection Store.

Storage layer for DRP components.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    Alert,
    AuditEvent,
    BrandImpersonation,
    CredentialExposure,
    DarkWebIntelligence,
    Domain,
    ExternalAttackSurface,
    PhishingAlert,
    RiskScore,
    RiskLevel,
    SocialMediaAbuse,
    ThreatStatus,
)


class DRPStore:
    """Store for digital risk protection."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._domains: Dict[str, Domain] = {}
        self._phishing_alerts: Dict[str, PhishingAlert] = {}
        self._brand_impersonations: Dict[str, BrandImpersonation] = {}
        self._credential_exposures: Dict[str, CredentialExposure] = {}
        self._darkweb_intel: Dict[str, DarkWebIntelligence] = {}
        self._social_abuse: Dict[str, SocialMediaAbuse] = {}
        self._attack_surfaces: Dict[str, ExternalAttackSurface] = {}
        self._risk_scores: Dict[str, RiskScore] = {}
        self._alerts: Dict[str, Alert] = {}
        self._audit_log: List[AuditEvent] = []
        self._lock = threading.RLock()

    def register_domain(self, domain: Domain) -> None:
        """Register a monitored domain."""
        with self._lock:
            self._domains[domain.domain_id] = domain

    def get_domain(self, domain_id: str) -> Optional[Domain]:
        """Get a domain by ID."""
        return self._domains.get(domain_id)

    def add_phishing_alert(self, alert: PhishingAlert) -> None:
        """Add a phishing alert."""
        with self._lock:
            self._phishing_alerts[alert.alert_id] = alert

    def get_phishing_alert(self, alert_id: str) -> Optional[PhishingAlert]:
        """Get a phishing alert."""
        return self._phishing_alerts.get(alert_id)

    def get_phishing_alerts(
        self,
        status: Optional[ThreatStatus] = None,
        limit: int = 100,
    ) -> List[PhishingAlert]:
        """Get phishing alerts."""
        alerts = list(self._phishing_alerts.values())
        if status:
            alerts = [a for a in alerts if a.status == status]
        alerts.sort(key=lambda x: x.created_at, reverse=True)
        return alerts[:limit]

    def add_brand_impersonation(self, impersonation: BrandImpersonation) -> None:
        """Add a brand impersonation record."""
        with self._lock:
            self._brand_impersonations[impersonation.impersonation_id] = impersonation

    def get_brand_impersonations(
        self,
        brand_name: Optional[str] = None,
    ) -> List[BrandImpersonation]:
        """Get brand impersonations."""
        impersonations = list(self._brand_impersonations.values())
        if brand_name:
            impersonations = [
                i for i in impersonations
                if brand_name.lower() in i.brand_name.lower()
            ]
        return impersonations

    def add_credential_exposure(self, exposure: CredentialExposure) -> None:
        """Add a credential exposure."""
        with self._lock:
            self._credential_exposures[exposure.exposure_id] = exposure

    def get_credential_exposures(self) -> List[CredentialExposure]:
        """Get credential exposures."""
        return list(self._credential_exposures.values())

    def add_darkweb_intel(self, intel: DarkWebIntelligence) -> None:
        """Add dark web intelligence."""
        with self._lock:
            self._darkweb_intel[intel.intel_id] = intel

    def get_darkweb_intel(
        self,
        min_confidence: float = 0.0,
    ) -> List[DarkWebIntelligence]:
        """Get dark web intelligence."""
        return [
            i for i in self._darkweb_intel.values()
            if i.confidence >= min_confidence
        ]

    def add_social_abuse(self, abuse: SocialMediaAbuse) -> None:
        """Add social media abuse record."""
        with self._lock:
            self._social_abuse[abuse.abuse_id] = abuse

    def get_social_abuse(
        self,
        platform: Optional[str] = None,
    ) -> List[SocialMediaAbuse]:
        """Get social media abuse records."""
        records = list(self._social_abuse.values())
        if platform:
            records = [r for r in records if r.platform == platform]
        return records

    def add_attack_surface(self, surface: ExternalAttackSurface) -> None:
        """Add an attack surface record."""
        with self._lock:
            self._attack_surfaces[surface.surface_id] = surface

    def get_attack_surfaces(self) -> List[ExternalAttackSurface]:
        """Get attack surface records."""
        return list(self._attack_surfaces.values())

    def store_risk_score(self, score: RiskScore) -> None:
        """Store a risk score."""
        with self._lock:
            self._risk_scores[score.organization_id] = score

    def get_risk_score(self, organization_id: str) -> Optional[RiskScore]:
        """Get risk score for an organization."""
        return self._risk_scores.get(organization_id)

    def add_alert(self, alert: Alert) -> None:
        """Add an alert."""
        with self._lock:
            self._alerts[alert.alert_id] = alert

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert."""
        return self._alerts.get(alert_id)

    def get_alerts(
        self,
        status: Optional[ThreatStatus] = None,
        severity: Optional[RiskLevel] = None,
    ) -> List[Alert]:
        """Get alerts."""
        alerts = list(self._alerts.values())
        if status:
            alerts = [a for a in alerts if a.status == status]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        alerts.sort(key=lambda x: x.created_at, reverse=True)
        return alerts

    def update_alert_status(self, alert_id: str, status: ThreatStatus) -> bool:
        """Update alert status."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        alert.status = status
        alert.updated_at = datetime.now(timezone.utc)
        return True

    def log_audit(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Log an audit event."""
        event = AuditEvent(
            event_id=f"audit-{len(self._audit_log) + 1}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            success=success,
        )
        with self._lock:
            self._audit_log.append(event)

    def get_audit_log(self, limit: int = 100) -> List[AuditEvent]:
        """Get audit log."""
        return self._audit_log[-limit:]

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get dashboard metrics."""
        return {
            "total_phishing_alerts": len(self._phishing_alerts),
            "active_phishing_alerts": len([
                a for a in self._phishing_alerts.values()
                if a.status in [ThreatStatus.NEW, ThreatStatus.INVESTIGATING]
            ]),
            "total_brand_impersonations": len(self._brand_impersonations),
            "total_credential_exposures": len(self._credential_exposures),
            "total_darkweb_intel": len(self._darkweb_intel),
            "total_social_abuse": len(self._social_abuse),
            "total_attack_surfaces": len(self._attack_surfaces),
            "total_alerts": len(self._alerts),
            "active_alerts": len([
                a for a in self._alerts.values()
                if a.status in [ThreatStatus.NEW, ThreatStatus.INVESTIGATING]
            ]),
        }

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._domains.clear()
            self._phishing_alerts.clear()
            self._brand_impersonations.clear()
            self._credential_exposures.clear()
            self._darkweb_intel.clear()
            self._social_abuse.clear()
            self._attack_surfaces.clear()
            self._risk_scores.clear()
            self._alerts.clear()
            self._audit_log.clear()


# Singleton instance
_store: Optional[DRPStore] = None
_store_lock = threading.Lock()


def get_drp_store() -> DRPStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = DRPStore()
    return _store


def reset_drp_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None