"""
Anomaly Detection Engine for AI Threat Hunting
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from .models import ThreatIndicator, IndicatorType, ThreatSeverity
from .store import ThreatHuntingStore, get_store


class AnomalyDetector:
    """Engine to perform transaction/session anomaly classification."""

    def __init__(self, store: Optional[ThreatHuntingStore] = None):
        self.store = store or get_store()

    def detect_anomalies(
        self,
        entity_id: str,
        operation: str,
        ip_address: str,
        device_status: str,
        failed_attempts: int,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatIndicator]:
        """Detect anomalies in the current context and register indicators."""
        attributes = attributes or {}
        detected_indicators: List[ThreatIndicator] = []

        # 1. Blocked/Suspicious Device Status
        if device_status in ("BLOCKED", "STOLEN", "LOST"):
            ind = ThreatIndicator(
                indicator_type=IndicatorType.FINGERPRINT,
                value=entity_id,
                description=f"Activity from device in {device_status} status",
                severity=ThreatSeverity.CRITICAL,
                confidence=0.9,
                attributes={"device_status": device_status},
            )
            self.store.register_indicator(ind)
            detected_indicators.append(ind)

        # 2. Authentication Failures Velocity
        if failed_attempts >= 3:
            severity = ThreatSeverity.HIGH if failed_attempts < 5 else ThreatSeverity.CRITICAL
            ind = ThreatIndicator(
                indicator_type=IndicatorType.VELOCITY,
                value=entity_id,
                description=f"High rate of authentication failures ({failed_attempts} attempts)",
                severity=severity,
                confidence=0.85,
                attributes={"failed_attempts": failed_attempts},
            )
            self.store.register_indicator(ind)
            detected_indicators.append(ind)

        # 3. High-Privilege or Sensitive Operations
        sensitive_ops = ("revoke_credentials", "export_data", "update_credentials", "delete_account")
        if operation in sensitive_ops:
            ind = ThreatIndicator(
                indicator_type=IndicatorType.BEHAVIOR,
                value=operation,
                description=f"Sensitive operation executed: '{operation}'",
                severity=ThreatSeverity.MEDIUM,
                confidence=0.7,
                attributes={"operation": operation},
            )
            self.store.register_indicator(ind)
            detected_indicators.append(ind)

        # 4. Anomalous IP Geolocation (e.g. proxy or cloud subnets)
        if ip_address.startswith("100.") or ip_address.startswith("200."):
            ind = ThreatIndicator(
                indicator_type=IndicatorType.IP,
                value=ip_address,
                description="Activity originating from suspected proxy IP subnet range",
                severity=ThreatSeverity.MEDIUM,
                confidence=0.6,
                attributes={"ip_address": ip_address},
            )
            self.store.register_indicator(ind)
            detected_indicators.append(ind)

        return detected_indicators
