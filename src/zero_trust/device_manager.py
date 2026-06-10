"""
Device Trust Manager for Zero Trust Security
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from .models import DeviceTrust, DeviceFingerprint, DeviceStatus
from .store import ZeroTrustStore, get_store


DEVICE_WEIGHTS = {
    "registration_age": 0.20, "verification_count": 0.15,
    "failed_verifications": 0.20, "risk_events": 0.25, "trust_history": 0.20,
}


class DeviceTrustManager:
    def __init__(self, store: Optional[ZeroTrustStore] = None):
        self.store = store or get_store()
        self.registration_count = 0

    def register_device(self, user_id: str, device_info: Dict[str, Any]) -> DeviceTrust:
        fingerprint = self._create_fingerprint(user_id, device_info)
        device_id = self._generate_device_id(fingerprint)
        device = DeviceTrust(device_id=device_id, fingerprint=fingerprint, status=DeviceStatus.REGISTERED, trust_score=0.5,
                             first_seen=datetime.now(timezone.utc).isoformat(), last_seen=datetime.now(timezone.utc).isoformat())
        existing = self.store.get_device(device_id)
        if existing:
            existing.last_seen = device.last_seen
            existing.verification_count += 1
            return existing
        result = self.store.register_device(device)
        self.registration_count += 1
        return result

    def _create_fingerprint(self, user_id: str, device_info: Dict[str, Any]) -> DeviceFingerprint:
        return DeviceFingerprint(user_id=user_id, device_type=device_info.get("device_type", "unknown"),
                                os_version=device_info.get("os_version", ""), browser=device_info.get("browser", ""),
                                browser_version=device_info.get("browser_version", ""),
                                screen_resolution=device_info.get("screen_resolution", ""),
                                timezone=device_info.get("timezone", ""), language=device_info.get("language", ""),
                                ip_address=device_info.get("ip_address", ""),
                                mac_address=device_info.get("mac_address"),
                                serial_number=device_info.get("serial_number"))

    def _generate_device_id(self, fingerprint: DeviceFingerprint) -> str:
        components = [fingerprint.hash, fingerprint.user_id, str(uuid.uuid4())[:8]]
        return hashlib.sha256("|".join(components).encode()).hexdigest()[:32]

    def get_device(self, device_id: str) -> Optional[DeviceTrust]:
        return self.store.get_device(device_id)

    def get_user_devices(self, user_id: str) -> List[DeviceTrust]:
        return self.store.get_user_devices(user_id)

    def verify_device(self, device_id: str, verification_data: Dict[str, Any]) -> bool:
        device = self.store.get_device(device_id)
        if not device:
            return False
        device.verification_count += 1
        device.last_verified = datetime.now(timezone.utc).isoformat()
        self._update_device_trust(device)
        return True

    def record_failed_verification(self, device_id: str, reason: str = "") -> Optional[DeviceTrust]:
        device = self.store.get_device(device_id)
        if not device:
            return None
        device.failed_verifications += 1
        self._update_device_trust(device)
        return device

    def record_risk_event(self, device_id: str, event_type: str, severity: str = "MEDIUM") -> Optional[DeviceTrust]:
        device = self.store.get_device(device_id)
        if not device:
            return None
        device.risk_events += 1
        if event_type not in device.tags:
            device.tags.append(event_type)
        if severity == "HIGH" and device.status == DeviceStatus.REGISTERED:
            device.status = DeviceStatus.BLOCKED
        self._update_device_trust(device)
        return device

    def block_device(self, device_id: str, reason: str = "") -> Optional[DeviceTrust]:
        device = self.store.get_device(device_id)
        if not device:
            return None
        device.status = DeviceStatus.BLOCKED
        device.attributes["block_reason"] = reason
        device.attributes["blocked_at"] = datetime.now(timezone.utc).isoformat()
        return device

    def unblock_device(self, device_id: str) -> Optional[DeviceTrust]:
        device = self.store.get_device(device_id)
        if not device:
            return None
        device.status = DeviceStatus.REGISTERED
        device.attributes.pop("block_reason", None)
        device.attributes.pop("blocked_at", None)
        return device

    def _update_device_trust(self, device: DeviceTrust):
        trust_score = self._calculate_reputation_score(device)
        device.trust_score = trust_score
        device.reputation_score = trust_score
        device.last_seen = datetime.now(timezone.utc).isoformat()

    def _calculate_reputation_score(self, device: DeviceTrust) -> float:
        try:
            first_seen = datetime.fromisoformat(device.first_seen.replace('Z', '+00:00'))
            age_days = (datetime.now(timezone.utc) - first_seen).days
            age_score = min(age_days / 30.0, 1.0) * 0.5 + 0.5
        except (ValueError, AttributeError):
            age_score = 0.5
        verify_score = min(device.verification_count / 10.0, 1.0) * 0.5 + 0.5
        fail_penalty = min(device.failed_verifications * 0.1, 0.5)
        fail_score = 1.0 - fail_penalty
        risk_penalty = min(device.risk_events * 0.15, 0.75)
        risk_score = 1.0 - risk_penalty
        history_score = device.trust_score
        return max(0.0, min(1.0, age_score * DEVICE_WEIGHTS["registration_age"] + verify_score * DEVICE_WEIGHTS["verification_count"] +
                           fail_score * DEVICE_WEIGHTS["failed_verifications"] + risk_score * DEVICE_WEIGHTS["risk_events"] +
                           history_score * DEVICE_WEIGHTS["trust_history"]))

    def evaluate_device_trust(self, device_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        device = self.store.get_device(device_id)
        if not device:
            return {"trusted": False, "reason": "Device not registered", "trust_score": 0.0, "required_actions": ["REGISTER_DEVICE"]}
        if device.status == DeviceStatus.BLOCKED:
            return {"trusted": False, "reason": "Device is blocked", "trust_score": 0.0, "block_reason": device.attributes.get("block_reason", "Unknown"), "required_actions": ["CONTACT_ADMIN"]}
        reputation = self._calculate_reputation_score(device)
        trusted = reputation >= 0.5 and device.status == DeviceStatus.REGISTERED
        actions = []
        if reputation < 0.3:
            actions.append("REQUIRE_MFA")
        if device.verification_count < 3:
            actions.append("VERIFY_DEVICE")
        if device.risk_events > 0:
            actions.append("ENHANCED_MONITORING")
        return {"trusted": trusted, "reason": "Device trusted" if trusted else "Device requires verification",
                "trust_score": reputation, "device_status": device.status.value if hasattr(device.status, 'value') else device.status,
                "verification_count": device.verification_count, "risk_events": device.risk_events,
                "required_actions": actions, "last_verified": device.last_verified}

    def get_device_stats(self) -> Dict[str, Any]:
        all_devices = list(self.store.devices.values())
        return {"total_devices": len(all_devices), "registered_devices": sum(1 for d in all_devices if d.status == DeviceStatus.REGISTERED),
                "blocked_devices": sum(1 for d in all_devices if d.status == DeviceStatus.BLOCKED),
                "devices_with_risk_events": sum(1 for d in all_devices if d.risk_events > 0),
                "devices_requiring_verification": sum(1 for d in all_devices if d.verification_count < 3),
                "registration_count": self.registration_count}

    def get_trusted_devices(self, user_id: str, min_score: float = 0.7) -> List[DeviceTrust]:
        devices = self.store.get_user_devices(user_id)
        return [d for d in devices if d.trust_score >= min_score and d.status == DeviceStatus.REGISTERED]