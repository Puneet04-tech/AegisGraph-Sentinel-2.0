"""
Digital Risk Protection Platform.

Enterprise platform for detecting phishing, brand impersonation,
credential exposures, dark web threats, and external attack surfaces.
"""

from .models import (
    # Enums
    RiskLevel,
    ThreatStatus,
    ThreatType,
    # Data Classes
    Alert,
    AuditEvent,
    BrandImpersonation,
    CredentialExposure,
    DarkWebIntelligence,
    Domain,
    ExternalAttackSurface,
    PhishingAlert,
    RiskScore,
    SocialMediaAbuse,
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

from .service import (
    DigitalRiskProtectionService,
    get_drp_service,
    reset_drp_service,
)

__all__ = [
    # Enums
    "RiskLevel",
    "ThreatStatus",
    "ThreatType",
    # Models
    "Alert",
    "AuditEvent",
    "BrandImpersonation",
    "CredentialExposure",
    "DarkWebIntelligence",
    "Domain",
    "ExternalAttackSurface",
    "PhishingAlert",
    "RiskScore",
    "SocialMediaAbuse",
    # Store
    "DRPStore",
    "get_drp_store",
    "reset_drp_store",
    # Engines
    "BrandProtectionEngine",
    "get_brand_protection_engine",
    "reset_brand_protection_engine",
    "PhishingDetectionEngine",
    "get_phishing_detector",
    "reset_phishing_detector",
    "DomainIntelligenceEngine",
    "get_domain_intelligence_engine",
    "reset_domain_intelligence_engine",
    "CredentialMonitor",
    "get_credential_monitor",
    "reset_credential_monitor",
    "DarkWebIntelligenceEngine",
    "get_darkweb_intelligence_engine",
    "reset_darkweb_intelligence_engine",
    "SocialMediaMonitor",
    "get_social_media_monitor",
    "reset_social_media_monitor",
    "RiskScoringEngine",
    "get_risk_engine",
    "reset_risk_engine",
    # Service
    "DigitalRiskProtectionService",
    "get_drp_service",
    "reset_drp_service",
]