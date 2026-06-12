"""
Brand Protection Engine.

Monitors brand impersonation and trademark abuse.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    Alert,
    BrandImpersonation,
    Domain,
    RiskLevel,
    ThreatStatus,
    ThreatType,
)
from .store import DRPStore, get_drp_store


class BrandProtectionEngine:
    """Engine for brand protection monitoring."""

    def __init__(self, store: Optional[DRPStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_drp_store()
        self._registered_brands: Dict[str, Dict[str, Any]] = {}

    def register_brand(
        self,
        brand_name: str,
        protected_domains: List[str],
        trademarks: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Register a brand for monitoring."""
        brand_id = f"brand-{uuid.uuid4().hex[:12]}"
        
        self._registered_brands[brand_id] = {
            "brand_id": brand_id,
            "brand_name": brand_name,
            "protected_domains": protected_domains,
            "trademarks": trademarks or [],
            "registered_at": datetime.now(timezone.utc),
        }
        
        return self._registered_brands[brand_id]

    def detect_impersonation(
        self,
        suspicious_domain: str,
        brand_name: Optional[str] = None,
    ) -> Optional[BrandImpersonation]:
        """Detect brand impersonation from a domain."""
        impersonations = []
        
        for brand_id, brand_info in self._registered_brands.items():
            if brand_name and brand_name.lower() != brand_info["brand_name"].lower():
                continue
            
            brand_lower = brand_info["brand_name"].lower()
            domain_lower = suspicious_domain.lower()
            
            if brand_lower in domain_lower:
                impersonation = BrandImpersonation(
                    impersonation_id=f"imp-{uuid.uuid4().hex[:12]}",
                    brand_name=brand_info["brand_name"],
                    impersonating_domain=suspicious_domain,
                    type="domain_impersonation",
                    status=ThreatStatus.NEW,
                    confidence=self._calculate_confidence(
                        suspicious_domain,
                        brand_info["protected_domains"],
                    ),
                )
                impersonations.append(impersonation)
        
        if impersonations:
            best = max(impersonations, key=lambda x: x.confidence)
            self.store.add_brand_impersonation(best)
            return best
        
        return None

    def _calculate_confidence(
        self,
        suspicious_domain: str,
        protected_domains: List[str],
    ) -> float:
        """Calculate impersonation confidence."""
        confidence = 0.5
        
        domain_lower = suspicious_domain.lower()
        
        for protected in protected_domains:
            protected_lower = protected.lower()
            
            if protected_lower in domain_lower:
                confidence += 0.3
            elif domain_lower in protected_lower:
                confidence += 0.2
            elif domain_lower.replace(".", "") in protected_lower.replace(".", ""):
                confidence += 0.15
        
        if suspicious_domain.count("-") > 1:
            confidence += 0.1
        
        return min(0.99, confidence)

    def get_brand_monitor_results(
        self,
        brand_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get brand monitoring results."""
        impersonations = self.store.get_brand_impersonations(brand_name)
        
        return [
            {
                "impersonation_id": i.impersonation_id,
                "brand_name": i.brand_name,
                "domain": i.impersonating_domain,
                "type": i.type,
                "status": i.status.value,
                "confidence": i.confidence,
                "created_at": i.created_at.isoformat(),
            }
            for i in impersonations
        ]

    def request_takedown(
        self,
        impersonation_id: str,
    ) -> Dict[str, Any]:
        """Request takedown for an impersonation."""
        impersonations = self.store.get_brand_impersonations()
        
        for imp in impersonations:
            if imp.impersonation_id == impersonation_id:
                imp.status = ThreatStatus.TAKEDOWN_REQUESTED
                return {"status": "success", "impersonation_id": impersonation_id}
        
        return {"status": "not_found"}


# Singleton instance
_engine: Optional[BrandProtectionEngine] = None


def get_brand_protection_engine() -> BrandProtectionEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = BrandProtectionEngine()
    return _engine


def reset_brand_protection_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None