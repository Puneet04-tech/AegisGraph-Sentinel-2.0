"""
Domain Intelligence Engine.

Domain monitoring and intelligence gathering.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
import re

from .models import Domain
from .store import DRPStore, get_drp_store


class DomainIntelligenceEngine:
    """Engine for domain intelligence."""

    def __init__(self, store: Optional[DRPStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_drp_store()
        self._monitored_domains: Dict[str, Dict[str, Any]] = {}

    def register_domain(
        self,
        domain: str,
        registrar: Optional[str] = None,
        nameservers: Optional[List[str]] = None,
    ) -> Domain:
        """Register a domain for monitoring."""
        domain_id = f"dom-{uuid.uuid4().hex[:12]}"
        
        domain_obj = Domain(
            domain_id=domain_id,
            domain=domain,
            registrar=registrar,
            nameservers=nameservers or [],
        )
        
        self.store.register_domain(domain_obj)
        
        self._monitored_domains[domain] = {
            "domain_id": domain_id,
            "domain": domain,
            "registered_at": datetime.now(timezone.utc),
        }
        
        return domain_obj

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze a domain for risk indicators."""
        risk_indicators = []
        risk_score = 0.0
        
        if domain.count("-") > 3:
            risk_indicators.append("Excessive hyphens in domain")
            risk_score += 0.2
        
        if len(domain) > 30:
            risk_indicators.append("Unusually long domain")
            risk_score += 0.15
        
        suspicious_tlds = [".xyz", ".top", ".work", ".click", ".link"]
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            risk_indicators.append("Suspicious TLD")
            risk_score += 0.15
        
        if re.search(r"\d{5,}", domain):
            risk_indicators.append("Contains long number sequences")
            risk_score += 0.1
        
        common_brands = ["paypal", "apple", "google", "amazon", "microsoft", "facebook"]
        domain_lower = domain.lower()
        for brand in common_brands:
            if brand in domain_lower and brand not in domain_lower.split(".")[0]:
                risk_indicators.append(f"May be impersonating {brand}")
                risk_score += 0.25
        
        return {
            "domain": domain,
            "risk_score": min(0.99, risk_score),
            "risk_indicators": risk_indicators,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_monitored_domains(self) -> List[Dict[str, Any]]:
        """Get all monitored domains."""
        return [
            {
                "domain_id": d.domain_id,
                "domain": d.domain,
                "registrar": d.registrar,
                "nameservers": d.nameservers,
            }
            for d in self.store._domains.values()
        ]


# Singleton instance
_engine: Optional[DomainIntelligenceEngine] = None


def get_domain_intelligence_engine() -> DomainIntelligenceEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = DomainIntelligenceEngine()
    return _engine


def reset_domain_intelligence_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None