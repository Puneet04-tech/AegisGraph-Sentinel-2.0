"""
Digital Risk Protection Service.

Main service for digital risk protection platform.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import (
    Alert,
    AuditEvent,
    RiskLevel,
    ThreatStatus,
    ThreatType,
)
from .store import (
    DRPStore,
    get_drp_store,
    reset_drp_store,
)
from .brand_monitor import (
    BrandProtectionEngine,
    get_brand_protection_engine,
    reset_brand_protection_engine,
)
from .phishing_detector import (
    PhishingDetectionEngine,
    get_phishing_detector,
    reset_phishing_detector,
)
from .domain_intelligence import (
    DomainIntelligenceEngine,
    get_domain_intelligence_engine,
    reset_domain_intelligence_engine,
)
from .credential_monitor import (
    CredentialMonitor,
    get_credential_monitor,
    reset_credential_monitor,
)
from .darkweb_intelligence import (
    DarkWebIntelligenceEngine,
    get_darkweb_intelligence_engine,
    reset_darkweb_intelligence_engine,
)
from .social_monitor import (
    SocialMediaMonitor,
    get_social_media_monitor,
    reset_social_media_monitor,
)
from .risk_engine import (
    RiskScoringEngine,
    get_risk_engine,
    reset_risk_engine,
)


class DigitalRiskProtectionService:
    """Main service for digital risk protection."""

    def __init__(self, store: Optional[DRPStore] = None) -> None:
        """Initialize the service."""
        self.store = store or get_drp_store()
        self.brand = get_brand_protection_engine()
        self.phishing = get_phishing_detector()
        self.domain = get_domain_intelligence_engine()
        self.credentials = get_credential_monitor()
        self.darkweb = get_darkweb_intelligence_engine()
        self.social = get_social_media_monitor()
        self.risk = get_risk_engine()

    async def scan_domain(self, url: str) -> Dict[str, Any]:
        """Scan a domain for phishing."""
        return self.phishing.scan_domain(url)

    async def get_phishing_alerts(
        self,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get phishing alerts."""
        return self.phishing.get_phishing_alerts(status)

    async def get_brand_monitor(self) -> List[Dict[str, Any]]:
        """Get brand monitoring results."""
        return self.brand.get_brand_monitor_results()

    async def register_brand(
        self,
        brand_name: str,
        protected_domains: List[str],
    ) -> Dict[str, Any]:
        """Register a brand for monitoring."""
        return self.brand.register_brand(brand_name, protected_domains)

    async def get_darkweb_intelligence(
        self,
        min_confidence: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Get dark web intelligence."""
        return self.darkweb.get_intelligence(min_confidence)

    async def get_credential_exposures(
        self,
        employee_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Get credential exposures."""
        return self.credentials.get_exposures(employee_only)

    async def add_credential_exposure(
        self,
        email: str,
        source: str,
    ) -> Dict[str, Any]:
        """Add a credential exposure."""
        exposure = self.credentials.add_exposure(email, source)
        return {
            "exposure_id": exposure.exposure_id,
            "email": exposure.email,
            "status": "added",
        }

    async def get_risks(
        self,
        organization_id: str = "default",
    ) -> Dict[str, Any]:
        """Get risk scores."""
        self.risk.calculate_risk_score(organization_id)
        return self.risk.get_risk_score(organization_id) or {}

    async def create_alert(
        self,
        alert_type: str,
        title: str,
        description: str,
        severity: str,
    ) -> Dict[str, Any]:
        """Create an alert."""
        from datetime import datetime, timezone
        import uuid
        
        alert = Alert(
            alert_id=f"alert-{uuid.uuid4().hex[:12]}",
            alert_type=ThreatType(alert_type),
            title=title,
            description=description,
            severity=RiskLevel(severity),
        )
        
        self.store.add_alert(alert)
        
        self.store.log_audit(
            user_id="system",
            action="alert_created",
            resource_type="alert",
            resource_id=alert.alert_id,
            details={"type": alert_type, "severity": severity},
        )
        
        return {
            "alert_id": alert.alert_id,
            "status": "created",
            "severity": severity,
        }

    async def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get alerts."""
        status_enum = ThreatStatus(status) if status else None
        severity_enum = RiskLevel(severity) if severity else None
        
        alerts = self.store.get_alerts(status_enum, severity_enum)
        
        return [
            {
                "alert_id": a.alert_id,
                "type": a.alert_type.value,
                "title": a.title,
                "severity": a.severity.value,
                "status": a.status.value,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ]

    async def get_dashboard(self) -> Dict[str, Any]:
        """Get executive dashboard."""
        metrics = self.store.get_dashboard_metrics()
        phishing = self.phishing.get_phishing_alerts()[:5]
        brand = self.brand.get_brand_monitor_results()[:5]
        darkweb = self.darkweb.get_intelligence()[:5]
        
        return {
            **metrics,
            "recent_phishing_alerts": phishing,
            "recent_brand_impersonations": brand,
            "recent_darkweb_intel": darkweb,
        }

    async def get_audit(
        self,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit log."""
        events = self.store.get_audit_log(limit)
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "user_id": e.user_id,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "success": e.success,
            }
            for e in events
        ]


# Singleton instance
_service: Optional[DigitalRiskProtectionService] = None


def get_drp_service() -> DigitalRiskProtectionService:
    """Get the global service instance."""
    global _service
    if _service is None:
        _service = DigitalRiskProtectionService()
    return _service


def reset_drp_service() -> None:
    """Reset the global service."""
    global _service
    _service = None
    reset_drp_store()
    reset_brand_protection_engine()
    reset_phishing_detector()
    reset_domain_intelligence_engine()
    reset_credential_monitor()
    reset_darkweb_intelligence_engine()
    reset_social_media_monitor()
    reset_risk_engine()