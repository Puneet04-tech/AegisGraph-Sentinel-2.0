"""
Zero Trust Service - Combined interface for all Zero Trust components
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from .models import TrustLevel, TrustScore, DeviceTrust, DeviceFingerprint, SessionRisk, Policy, EvaluationContext
from .store import ZeroTrustStore, get_store
from .trust_engine import TrustEngine
from .device_manager import DeviceTrustManager
from .session_analyzer import SessionRiskAnalyzer
from .policy_engine import PolicyEnforcementEngine


class ZeroTrustService:
    def __init__(self, store: Optional[ZeroTrustStore] = None):
        self.store = store or get_store()
        self.trust_engine = TrustEngine(self.store)
        self.device_manager = DeviceTrustManager(self.store)
        self.session_analyzer = SessionRiskAnalyzer(self.store)
        self.policy_engine = PolicyEnforcementEngine(self.store)
        self.total_requests = 0
        self.blocked_requests = 0
        self.allowed_requests = 0
        self.challenged_requests = 0

    def evaluate(self, user_id: str, device_id: Optional[str] = None, session_id: Optional[str] = None,
                 ip_address: Optional[str] = None, location: Optional[Dict[str, Any]] = None,
                 user_agent: Optional[str] = None, resource: Optional[str] = None, action: Optional[str] = None,
                 authentication_method: Optional[str] = None, authentication_strength: float = 0.5,
                 device_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        start_time = time.time()
        self.total_requests += 1

        device_fingerprint = None
        if device_info:
            device_fingerprint = self.device_manager._create_fingerprint(user_id, device_info)

        context = EvaluationContext(user_id=user_id, session_id=session_id, device_id=device_id,
                                    device_fingerprint=device_fingerprint, ip_address=ip_address, user_agent=user_agent,
                                    location=location, requested_resource=resource, requested_action=action,
                                    authentication_method=authentication_method, authentication_strength=authentication_strength)

        trust_score = self.trust_engine.evaluate_trust(context)

        device_trust_result = None
        registered_device_id = device_id
        if device_id:
            device_trust_result = self.device_manager.evaluate_device_trust(device_id)
        elif device_info:
            device = self.device_manager.register_device(user_id, device_info)
            registered_device_id = device.device_id
            device_trust_result = self.device_manager.evaluate_device_trust(device.device_id)

        session_risk = None
        if session_id:
            session_risk = self.session_analyzer.analyze_session(context)
        elif user_id:
            session_risk = self.session_analyzer.analyze_session(context)
            session_id = session_risk.session_id

        policy_result = self.policy_engine.evaluate_access(context=context, trust_score=trust_score, resource=resource, action=action)

        final_decision = self._determine_final_decision(trust_score, device_trust_result, session_risk, policy_result)

        if final_decision == "BLOCK":
            self.blocked_requests += 1
        elif final_decision == "ALLOW":
            self.allowed_requests += 1
        else:
            self.challenged_requests += 1

        processing_time = (time.time() - start_time) * 1000

        return {"user_id": user_id, "session_id": session_id, "device_id": registered_device_id,
                "trust_score": trust_score.to_dict(), "device_trust": device_trust_result,
                "session_risk": session_risk.to_dict() if session_risk else None,
                "policy_evaluation": {"decision": policy_result.decision, "matched_policies": policy_result.matched_policies,
                                     "failed_policies": policy_result.failed_policies,
                                     "required_actions": policy_result.required_actions,
                                     "evaluation_time_ms": policy_result.evaluation_time_ms},
                "final_decision": final_decision,
                "recommendations": self._generate_recommendations(trust_score, device_trust_result, session_risk, policy_result),
                "processing_time_ms": processing_time, "timestamp": datetime.now(timezone.utc).isoformat()}

    def _determine_final_decision(self, trust_score: TrustScore, device_trust: Optional[Dict[str, Any]],
                                  session_risk: Optional[SessionRisk], policy_result) -> str:
        if policy_result.decision == "DENY" or policy_result.decision == "TERMINATE":
            return "BLOCK"
        if policy_result.decision == "CHALLENGE":
            return "CHALLENGE"
        if trust_score.level in (TrustLevel.BLOCKED, TrustLevel.UNTRUSTED):
            return "BLOCK"
        if device_trust and not device_trust.get("trusted", False):
            return "CHALLENGE"
        if session_risk and session_risk.risk_level.value in ("HIGH", "CRITICAL"):
            return "CHALLENGE"
        if trust_score.score < 0.3:
            return "CHALLENGE"
        return "ALLOW"

    def _generate_recommendations(self, trust_score: TrustScore, device_trust: Optional[Dict[str, Any]],
                                  session_risk: Optional[SessionRisk], policy_result) -> List[str]:
        recommendations = []
        recommendations.extend(trust_score.recommendations)
        recommendations.extend(policy_result.required_actions)
        if device_trust and device_trust.get("required_actions"):
            recommendations.extend(device_trust["required_actions"])
        if session_risk and session_risk.recommended_actions:
            recommendations.extend(session_risk.recommended_actions)
        return list(set(recommendations))

    def register_device(self, user_id: str, device_info: Dict[str, Any]) -> Dict[str, Any]:
        device = self.device_manager.register_device(user_id, device_info)
        return device.to_dict()

    def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        device = self.device_manager.get_device(device_id)
        return device.to_dict() if device else None

    def get_user_devices(self, user_id: str) -> List[Dict[str, Any]]:
        devices = self.device_manager.get_user_devices(user_id)
        return [d.to_dict() for d in devices]

    def verify_device(self, device_id: str, verification_data: Dict[str, Any]) -> Dict[str, Any]:
        success = self.device_manager.verify_device(device_id, verification_data)
        device = self.device_manager.get_device(device_id)
        return {"success": success, "device": device.to_dict() if device else None}

    def block_device(self, device_id: str, reason: str = "") -> Optional[Dict[str, Any]]:
        device = self.device_manager.block_device(device_id, reason)
        return device.to_dict() if device else None

    def unblock_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        device = self.device_manager.unblock_device(device_id)
        return device.to_dict() if device else None

    def analyze_session(self, user_id: str, context_data: Dict[str, Any]) -> Dict[str, Any]:
        context = EvaluationContext(user_id=user_id, session_id=context_data.get("session_id"),
                                    device_id=context_data.get("device_id"), ip_address=context_data.get("ip_address"),
                                    location=context_data.get("location"), user_agent=context_data.get("user_agent"),
                                    requested_resource=context_data.get("resource"),
                                    requested_action=context_data.get("action"),
                                    authentication_method=context_data.get("auth_method"),
                                    authentication_strength=context_data.get("auth_strength", 0.5),
                                    session_attributes=context_data.get("session_attributes", {}))
        session = self.session_analyzer.analyze_session(context)
        return session.to_dict()

    def get_session_risk(self, session_id: str) -> Optional[Dict[str, Any]]:
        session = self.session_analyzer.get_session_risk(session_id)
        return session.to_dict() if session else None

    def get_user_anomalies(self, user_id: str) -> Dict[str, Any]:
        return self.session_analyzer.get_user_anomaly_summary(user_id)

    def get_policies(self) -> List[Dict[str, Any]]:
        policies = self.policy_engine.get_policies()
        return [p.to_dict() for p in policies]

    def create_policy(self, name: str, description: str, conditions: Dict[str, Any],
                     actions: Dict[str, Any], priority: int = 50) -> Dict[str, Any]:
        policy = self.policy_engine.create_policy(name=name, description=description, conditions=conditions,
                                                  actions=actions, priority=priority)
        return policy.to_dict()

    def update_policy(self, policy_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        policy = self.policy_engine.update_policy(policy_id, **kwargs)
        return policy.to_dict() if policy else None

    def delete_policy(self, policy_id: str) -> bool:
        return self.policy_engine.delete_policy(policy_id)

    def get_stats(self) -> Dict[str, Any]:
        return {"service_stats": {"total_requests": self.total_requests, "blocked_requests": self.blocked_requests,
                                  "allowed_requests": self.allowed_requests, "challenged_requests": self.challenged_requests,
                                  "block_rate": self.blocked_requests / self.total_requests if self.total_requests > 0 else 0},
                "trust_engine": self.trust_engine.get_stats(), "device_manager": self.device_manager.get_device_stats(),
                "session_analyzer": self.session_analyzer.get_analyzer_stats(),
                "policy_engine": self.policy_engine.get_engine_stats(), "store": self.store.get_stats()}

    def reset_stats(self):
        self.total_requests = 0
        self.blocked_requests = 0
        self.allowed_requests = 0
        self.challenged_requests = 0
        self.trust_engine.reset_stats()
        self.policy_engine.reset_stats()


_service: Optional[ZeroTrustService] = None
_service_lock = None


def get_zero_trust_service() -> ZeroTrustService:
    global _service, _service_lock
    if _service_lock is None:
        import threading
        _service_lock = threading.Lock()
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = ZeroTrustService()
    return _service