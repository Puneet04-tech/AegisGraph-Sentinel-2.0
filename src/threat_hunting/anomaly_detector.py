"""
Anomaly Detection Engine for AI Threat Hunting
"""

from __future__ import annotations

from typing import Dict, List, Any, Optional

from .models import ThreatIndicator, IndicatorType, ThreatSeverity
from .store import ThreatHuntingStore, get_store


class AnomalyDetector:
    """Detects threat anomalies from entity activity signals.

    Evaluates device status, failed authentication attempts, sensitive
    operations, and IP address characteristics to surface security-relevant
    indicators stored in the threat-hunting store.
    """

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
        """Detect threat indicators from entity activity.

        Args:
            entity_id: Identifier of the entity being evaluated.
            operation: The operation or action the entity performed.
            ip_address: Source IP address of the activity.
            device_status: Status of the device (e.g. BLOCKED, ACTIVE).
            failed_attempts: Number of failed authentication attempts.
            attributes: Optional additional attributes to consider.

        Returns:
            List of ThreatIndicator objects detected from the signals.
        """
        self,
        entity_id: str,
        operation: str,
        ip_address: str,
        device_status: str,
        failed_attempts: int,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatIndicator]:
        attributes = attributes or {}
        detected_indicators: List[ThreatIndicator] = []

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

        if failed_attempts >= 3:
            severity = ThreatSeverity.HIGH if failed_attempts < 5 else ThreatSeverity.CRITICAL
            ind = ThreatIndicator(
                indicator_type=IndicatorType.VELOCITY,
                value=entity_id,
                description=f"High rate of auth failures ({failed_attempts} attempts)",
                severity=severity,
                confidence=0.85,
                attributes={"failed_attempts": failed_attempts},
            )
            self.store.register_indicator(ind)
            detected_indicators.append(ind)

        sensitive_ops = ("revoke_credentials", "export_data", "update_credentials", "delete_account")
        if operation in sensitive_ops:
            ind = ThreatIndicator(
                indicator_type=IndicatorType.BEHAVIOR,
                value=operation,
                description=f"Sensitive operation: '{operation}'",
                severity=ThreatSeverity.MEDIUM,
                confidence=0.7,
                attributes={"operation": operation},
            )
            self.store.register_indicator(ind)
            detected_indicators.append(ind)

        if ip_address.startswith("100.") or ip_address.startswith("200."):
            ind = ThreatIndicator(
                indicator_type=IndicatorType.IP,
                value=ip_address,
                description="Activity from suspected proxy IP subnet",
                severity=ThreatSeverity.MEDIUM,
                confidence=0.6,
                attributes={"ip_address": ip_address},
            )
            self.store.register_indicator(ind)
            detected_indicators.append(ind)

        return detected_indicators

