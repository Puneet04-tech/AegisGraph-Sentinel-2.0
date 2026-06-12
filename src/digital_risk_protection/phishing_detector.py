"""
Phishing Detection Engine.

Detects phishing domains and sites targeting organizations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
import re

from .models import (
    Alert,
    PhishingAlert,
    RiskLevel,
    ThreatStatus,
    ThreatType,
)
from .store import DRPStore, get_drp_store


class PhishingDetectionEngine:
    """Engine for phishing detection."""

    def __init__(self, store: Optional[DRPStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_drp_store()
        self._protected_brands: Dict[str, List[str]] = {}

    def register_brand(self, brand_name: str, protected_domains: List[str]) -> None:
        """Register a brand for phishing protection."""
        self._protected_brands[brand_name.lower()] = protected_domains

    def scan_domain(self, url: str) -> Dict[str, Any]:
        """Scan a domain for phishing indicators."""
        phishing_indicators = self._analyze_phishing_indicators(url)
        risk_score = self._calculate_risk_score(phishing_indicators)
        
        target_brand = self._identify_target_brand(url)
        
        alert = PhishingAlert(
            alert_id=f"phish-{uuid.uuid4().hex[:12]}",
            target_domain=target_brand or "unknown",
            phishing_url=url,
            target_brand=target_brand,
            status=ThreatStatus.NEW,
            confidence=risk_score,
            risk_level=self._score_to_risk_level(risk_score),
        )
        
        self.store.add_phishing_alert(alert)
        
        self.store.log_audit(
            user_id="system",
            action="domain_scan",
            resource_type="phishing_alert",
            resource_id=alert.alert_id,
            details={"url": url, "risk_score": risk_score},
        )
        
        return {
            "alert_id": alert.alert_id,
            "url": url,
            "target_brand": target_brand,
            "risk_score": risk_score,
            "risk_level": alert.risk_level.value,
            "indicators": phishing_indicators,
        }

    def _analyze_phishing_indicators(self, url: str) -> Dict[str, Any]:
        """Analyze phishing indicators."""
        indicators = {
            "suspicious_tld": False,
            "homograph_chars": False,
            "ip_address_url": False,
            "excessive_subdomains": False,
            "brand_misspelling": False,
            "suspicious_path": False,
        }
        
        if url.count(".") > 3:
            indicators["excessive_subdomains"] = True
        
        if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
            indicators["ip_address_url"] = True
        
        suspicious_tlds = [".xyz", ".top", ".club", ".online", ".site", ".work"]
        if any(url.endswith(tld) for tld in suspicious_tlds):
            indicators["suspicious_tld"] = True
        
        if any(ord(c) > 127 for c in url):
            indicators["homograph_chars"] = True
        
        suspicious_paths = ["/login", "/signin", "/account", "/verify", "/secure"]
        if any(p in url.lower() for p in suspicious_paths):
            indicators["suspicious_path"] = True
        
        return indicators

    def _identify_target_brand(self, url: str) -> Optional[str]:
        """Identify the target brand from URL."""
        url_lower = url.lower()
        
        brand_keywords = {
            "paypal": ["paypal", "paypa1", "paypa1"],
            "apple": ["apple", "app1e"],
            "microsoft": ["microsoft", "micros0ft", "micros0ft"],
            "google": ["google", "g00gle"],
            "amazon": ["amazon", "amaz0n"],
            "facebook": ["facebook", "faceb00k"],
            "netflix": ["netflix", "netf1ix"],
        }
        
        for brand, keywords in brand_keywords.items():
            if any(kw in url_lower for kw in keywords):
                return brand
        
        return None

    def _calculate_risk_score(self, indicators: Dict[str, Any]) -> float:
        """Calculate overall risk score."""
        score = 0.0
        
        weights = {
            "suspicious_tld": 0.1,
            "homograph_chars": 0.15,
            "ip_address_url": 0.2,
            "excessive_subdomains": 0.1,
            "brand_misspelling": 0.25,
            "suspicious_path": 0.15,
        }
        
        for indicator, present in indicators.items():
            if present:
                score += weights.get(indicator, 0.1)
        
        return min(0.99, score)

    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert score to risk level."""
        if score >= 0.7:
            return RiskLevel.CRITICAL
        elif score >= 0.5:
            return RiskLevel.HIGH
        elif score >= 0.3:
            return RiskLevel.MEDIUM
        elif score >= 0.1:
            return RiskLevel.LOW
        return RiskLevel.INFO

    def get_phishing_alerts(
        self,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get phishing alerts."""
        status_enum = ThreatStatus(status) if status else None
        alerts = self.store.get_phishing_alerts(status_enum)
        
        return [
            {
                "alert_id": a.alert_id,
                "target_domain": a.target_domain,
                "url": a.phishing_url,
                "target_brand": a.target_brand,
                "status": a.status.value,
                "confidence": a.confidence,
                "risk_level": a.risk_level.value,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ]

    def update_alert_status(
        self,
        alert_id: str,
        status: str,
    ) -> Dict[str, Any]:
        """Update alert status."""
        status_enum = ThreatStatus(status)
        success = self.store.update_alert_status(alert_id, status_enum)
        
        return {"success": success, "alert_id": alert_id, "status": status}


# Singleton instance
_engine: Optional[PhishingDetectionEngine] = None


def get_phishing_detector() -> PhishingDetectionEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = PhishingDetectionEngine()
    return _engine


def reset_phishing_detector() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None