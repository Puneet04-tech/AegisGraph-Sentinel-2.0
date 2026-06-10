"""
In-memory store for Zero Trust data with O(1) lookup optimization
"""

from __future__ import annotations

import time
import threading
from collections import OrderedDict
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .models import (
    TrustScore,
    DeviceTrust,
    DeviceStatus,
    SessionRisk,
    Policy,
    EvaluationContext,
    TrustLevel,
)


class LRUCache(OrderedDict):
    def __init__(self, maxsize: int = 10000, *args, **kwargs):
        self.maxsize = maxsize
        self.lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def __getitem__(self, key):
        with self.lock:
            value = super().__getitem__(key)
            self.move_to_end(key)
            return value

    def __setitem__(self, key, value):
        with self.lock:
            if key in self:
                self.move_to_end(key)
            super().__setitem__(key, value)
            if len(self) > self.maxsize:
                oldest = next(iter(self))
                del self[oldest]

    def get(self, key, default=None):
        with self.lock:
            try:
                self.move_to_end(key)
                return super().__getitem__(key)
            except KeyError:
                return default


@dataclass
class CacheEntry:
    value: Any
    created_at: float = field(default_factory=time.time)
    ttl: float = 300.0

    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl


class ZeroTrustStore:
    def __init__(self, cache_size: int = 10000, default_ttl: float = 300.0):
        self.cache_size = cache_size
        self.default_ttl = default_ttl
        self.lock = threading.RLock()
        self.trust_scores: LRUCache = LRUCache(maxsize=cache_size)
        self.devices: Dict[str, DeviceTrust] = {}
        self.sessions: Dict[str, SessionRisk] = {}
        self.policies: Dict[str, Policy] = {}
        self.evaluation_history: List[Dict[str, Any]] = []
        self.max_history = 10000
        self.stats = {
            "trust_evaluations": 0,
            "device_registrations": 0,
            "session_analyzes": 0,
            "policy_evaluations": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }
        self._init_default_policies()

    def _init_default_policies(self):
        default_policies = [
            Policy(policy_id="default-high-risk", name="High Risk User Policy",
                   description="Block or verify high risk users", priority=1,
                   conditions={"trust_score_below": 0.3},
                   actions={"decision": "DENY", "require_mfa": True}, scope={"all_users": True}),
            Policy(policy_id="default-new-device", name="New Device Policy",
                   description="Additional verification for new devices", priority=5,
                   conditions={"device_age_below_days": 1},
                   actions={"decision": "CHALLENGE", "require_device_verification": True}, scope={"all_users": True}),
            Policy(policy_id="default-suspicious-location", name="Suspicious Location Policy",
                   description="Verify access from suspicious locations", priority=3,
                   conditions={"location_risk_above": 0.7},
                   actions={"decision": "CHALLENGE", "require_location_verification": True}, scope={"all_users": True}),
            Policy(policy_id="default-anomaly-detected", name="Anomaly Response Policy",
                   description="Respond to detected anomalies", priority=2,
                   conditions={"behavioral_anomaly_score_above": 0.6},
                   actions={"decision": "CHALLENGE", "log_session": True, "notify_security": True}, scope={"all_users": True}),
            Policy(policy_id="default-trusted-access", name="Trusted Access Policy",
                   description="Allow trusted users with minimal friction", priority=100,
                   conditions={"trust_score_above": 0.8, "device_verified": True},
                   actions={"decision": "ALLOW", "reduced_logging": True}, scope={"all_users": True}),
        ]
        for policy in default_policies:
            self.policies[policy.policy_id] = policy

    def get_trust_score(self, user_id: str, device_id: Optional[str] = None) -> Optional[TrustScore]:
        key = self._trust_key(user_id, device_id)
        entry = self.trust_scores.get(key)
        if entry and isinstance(entry, CacheEntry):
            if not entry.is_expired():
                self.stats["cache_hits"] += 1
                return entry.value
            else:
                del self.trust_scores[key]
        self.stats["cache_misses"] += 1
        return None

    def set_trust_score(self, user_id: str, device_id: Optional[str], score: TrustScore, ttl: float = None):
        key = self._trust_key(user_id, device_id)
        entry_ttl = ttl if ttl is not None else self.default_ttl
        self.trust_scores[key] = CacheEntry(value=score, ttl=entry_ttl)

    def _trust_key(self, user_id: str, device_id: Optional[str]) -> str:
        return f"trust:{user_id}:{device_id}" if device_id else f"trust:{user_id}"

    def register_device(self, device: DeviceTrust) -> DeviceTrust:
        with self.lock:
            if device.status == DeviceStatus.UNKNOWN:
                device.status = DeviceStatus.REGISTERED
            device.last_seen = datetime.now(timezone.utc).isoformat()
            self.devices[device.device_id] = device
            self.stats["device_registrations"] += 1
        return device

    def get_device(self, device_id: str) -> Optional[DeviceTrust]:
        with self.lock:
            return self.devices.get(device_id)

    def get_user_devices(self, user_id: str) -> List[DeviceTrust]:
        with self.lock:
            return [d for d in self.devices.values() if d.fingerprint.user_id == user_id]

    def create_session_risk(self, session: SessionRisk) -> SessionRisk:
        with self.lock:
            self.sessions[session.session_id] = session
            self.stats["session_analyzes"] += 1
        return session

    def get_session_risk(self, session_id: str) -> Optional[SessionRisk]:
        with self.lock:
            return self.sessions.get(session_id)

    def get_user_sessions(self, user_id: str) -> List[SessionRisk]:
        with self.lock:
            return [s for s in self.sessions.values() if s.user_id == user_id]

    def get_all_policies(self) -> List[Policy]:
        with self.lock:
            return sorted(list(self.policies.values()), key=lambda p: p.priority)

    def get_enabled_policies(self) -> List[Policy]:
        with self.lock:
            return sorted([p for p in self.policies.values() if p.enabled], key=lambda p: p.priority)

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        with self.lock:
            return self.policies.get(policy_id)

    def add_policy(self, policy: Policy) -> Policy:
        with self.lock:
            self.policies[policy.policy_id] = policy
        return policy

    def update_policy(self, policy_id: str, **kwargs) -> Optional[Policy]:
        with self.lock:
            policy = self.policies.get(policy_id)
            if policy:
                for key, value in kwargs.items():
                    if hasattr(policy, key):
                        setattr(policy, key, value)
                policy.updated_at = datetime.now(timezone.utc).isoformat()
                return policy
        return None

    def delete_policy(self, policy_id: str) -> bool:
        with self.lock:
            if policy_id in self.policies:
                del self.policies[policy_id]
                return True
        return False

    def record_evaluation(self, context: EvaluationContext, result: Dict[str, Any]):
        with self.lock:
            entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "user_id": context.user_id,
                     "session_id": context.session_id, "device_id": context.device_id, "result": result}
            self.evaluation_history.append(entry)
            self.stats["trust_evaluations"] += 1
            if len(self.evaluation_history) > self.max_history:
                self.evaluation_history = self.evaluation_history[-self.max_history:]

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "trust_scores_cached": len(self.trust_scores),
                "devices_registered": len(self.devices),
                "active_sessions": len(self.sessions),
                "policies_configured": len(self.policies),
                "evaluation_history_size": len(self.evaluation_history),
                "stats": self.stats.copy(),
            }

    def reset_stats(self):
        with self.lock:
            for key in self.stats:
                self.stats[key] = 0


_store: Optional[ZeroTrustStore] = None
_store_lock = threading.Lock()


def get_store() -> ZeroTrustStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = ZeroTrustStore()
    return _store