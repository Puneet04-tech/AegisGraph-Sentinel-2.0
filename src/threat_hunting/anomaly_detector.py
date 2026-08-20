"""
Anomaly Detection Engine for AI Threat Hunting
"""

from __future__ import annotations

from typing import Dict, List, Any, Optional

from .models import ThreatIndicator, IndicatorType, ThreatSeverity
from .store import ThreatHuntingStore, get_store


class AnomalyDetector:
    """Detects anomalous activity based on entity behavior signals.

    Evaluates login failures, device status, sensitive operations, and IP subnets
    to produce ThreatIndicator records stored in the hunting store.
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
        """Detect anomalous activity for a given entity.

        Evaluates device status, authentication failure rates, sensitive operations,
        and IP address characteristics to generate threat indicators.

        Args:
            entity_id: Unique identifier of the entity being evaluated.
            operation: Name of the operation being performed.
            ip_address: Source IP address of the request.
            device_status: Current status of the device (e.g., BLOCKED, STOLEN).
            failed_attempts: Number of consecutive authentication failures.
            attributes: Optional additional context attributes.

        Returns:
            A list of ThreatIndicator objects representing detected anomalies.
        """
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

