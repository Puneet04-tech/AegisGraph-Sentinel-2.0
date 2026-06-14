"""
Policy Enforcement Engine for Zero Trust Security
"""

from __future__ import annotations

import time
import operator
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from dataclasses import dataclass

from .models import Policy, PolicyResult, EvaluationContext, TrustLevel, TrustScore
from .store import ZeroTrustStore, get_store


class PolicyDecision:
    ALLOW = "ALLOW"
    DENY = "DENY"
    CHALLENGE = "CHALLENGE"
    TERMINATE = "TERMINATE"


OPERATORS = {
    "eq": operator.eq, "ne": operator.ne, "gt": operator.gt, "gte": operator.ge,
    "lt": operator.lt, "lte": operator.le, "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b, "contains": lambda a, b: b in a,
    "startswith": lambda a, b: str(a).startswith(str(b)),
    "endswith": lambda a, b: str(a).endswith(str(b)),
}


@dataclass
class EvaluationResult:
    allowed: bool
    decision: str
    matched_policies: List[str]
    failed_policies: List[str]
    required_actions: List[str]
    risk_adjustments: List[float]
    session_flags: List[str]
    evaluation_time_ms: float


class PolicyEnforcementEngine:
    def __init__(self, store: Optional[ZeroTrustStore] = None):
        self.store = store or get_store()
        self.evaluation_count = 0
        self.total_evaluation_time = 0.0

    def evaluate_access(self, context: EvaluationContext, trust_score: Optional[TrustScore] = None,
                       resource: Optional[str] = None, action: Optional[str] = None) -> EvaluationResult:
        start_time = time.time()
        if resource:
            context.requested_resource = resource
        if action:
            context.requested_action = action

        policies = self.store.get_enabled_policies()
        matched_policies = []
        failed_policies = []
        all_required_actions = []
        risk_adjustments = []
        session_flags = []

        for policy in policies:
            result = self._evaluate_policy(policy, context, trust_score)
            if result.allowed:
                matched_policies.append(policy.policy_id)
                all_required_actions.extend(result.required_actions)
                risk_adjustments.append(result.risk_adjustment)
                session_flags.extend(result.session_flags)
                if result.decision == PolicyDecision.TERMINATE:
                    break
            else:
                failed_policies.append(policy.policy_id)

        decision, allowed = self._determine_final_decision(matched_policies, failed_policies, trust_score)
        all_required_actions = list(set(all_required_actions))
        session_flags = list(set(session_flags))
        evaluation_time = (time.time() - start_time) * 1000
        self.evaluation_count += 1
        self.total_evaluation_time += evaluation_time

        return EvaluationResult(allowed=allowed, decision=decision, matched_policies=matched_policies,
                                failed_policies=failed_policies, required_actions=all_required_actions,
                                risk_adjustments=risk_adjustments, session_flags=session_flags,
                                evaluation_time_ms=evaluation_time)

    def _evaluate_policy(self, policy: Policy, context: EvaluationContext, trust_score: Optional[TrustScore]) -> PolicyResult:
        result = PolicyResult(policy_id=policy.policy_id, policy_name=policy.name)
        conditions_met = True
        failed_conditions = []
        matched_conditions = []

        for condition_key, condition_value in policy.conditions.items():
            if self._evaluate_condition(condition_key, condition_value, context, trust_score):
                matched_conditions.append(condition_key)
            else:
                conditions_met = False
                failed_conditions.append(condition_key)

        result.matched_conditions = matched_conditions
        result.failed_conditions = failed_conditions

        if conditions_met:
            result.allowed = True
            result.decision = policy.actions.get("decision", PolicyDecision.ALLOW)
            result.required_actions = policy.actions.get("required_actions", [])
            result.risk_adjustment = policy.actions.get("risk_adjustment", 0.0)
            result.session_flags = policy.actions.get("session_flags", [])

        return result

    def _evaluate_condition(self, condition_key: str, condition_value: Any, context: EvaluationContext,
                           trust_score: Optional[TrustScore]) -> bool:
        if condition_key == "trust_score_below":
            return trust_score and trust_score.score < condition_value
        if condition_key == "trust_score_above":
            return trust_score and trust_score.score >= condition_value
        if condition_key == "trust_level_in":
            if trust_score:
                return trust_score.level.value in condition_value if isinstance(condition_value, list) else trust_score.level.value == condition_value
            return False
        if condition_key == "device_age_below_days":
            if context.device_id:
                device = self.store.get_device(context.device_id)
                if device:
                    try:
                        first_seen = datetime.fromisoformat(device.first_seen.replace('Z', '+00:00'))
                        age_days = (datetime.now(timezone.utc) - first_seen).days
                        return age_days < condition_value
                    except (ValueError, AttributeError):
                        return True
            return False
        if condition_key == "device_verified":
            if context.device_id:
                device = self.store.get_device(context.device_id)
                if device:
                    return device.verification_count >= condition_value
            return False
        if condition_key == "behavioral_anomaly_score_above":
            if trust_score and hasattr(trust_score.factors, 'behavioral_anomaly_score'):
                return trust_score.factors.behavioral_anomaly_score > condition_value
            return False
        if condition_key == "location_risk_above":
            if trust_score and hasattr(trust_score.factors, 'location_risk'):
                return trust_score.factors.location_risk > condition_value
            return False
        if condition_key == "all_users":
            return condition_value
        return False

    def _determine_final_decision(self, matched_policies: List[str], failed_policies: List[str],
                                   trust_score: Optional[TrustScore]) -> tuple[str, bool]:
        if failed_policies:
            for policy_id in failed_policies:
                policy = self.store.get_policy(policy_id)
                if policy and policy.priority < 50:
                    return PolicyDecision.DENY, False
        if not matched_policies:
            if trust_score:
                if trust_score.level in (TrustLevel.BLOCKED, TrustLevel.UNTRUSTED):
                    return PolicyDecision.DENY, False
                elif trust_score.level == TrustLevel.SUSPICIOUS:
                    return PolicyDecision.CHALLENGE, False
                else:
                    return PolicyDecision.ALLOW, True
            return PolicyDecision.DENY, False
        for policy_id in matched_policies:
            policy = self.store.get_policy(policy_id)
            if policy and policy.actions.get("decision") == PolicyDecision.CHALLENGE:
                return PolicyDecision.CHALLENGE, False
        return PolicyDecision.ALLOW, True

    def create_policy(self, name: str, description: str, conditions: Dict[str, Any],
                     actions: Dict[str, Any], priority: int = 50, scope: Optional[Dict[str, Any]] = None) -> Policy:
        policy = Policy(name=name, description=description, conditions=conditions, actions=actions,
                        priority=priority, scope=scope or {})
        return self.store.add_policy(policy)

    def update_policy(self, policy_id: str, **kwargs) -> Optional[Policy]:
        return self.store.update_policy(policy_id, **kwargs)

    def delete_policy(self, policy_id: str) -> bool:
        return self.store.delete_policy(policy_id)

    def get_policies(self) -> List[Policy]:
        return self.store.get_all_policies()

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        return self.store.get_policy(policy_id)

    def evaluate_policy_syntax(self, conditions: Dict[str, Any]) -> tuple[bool, List[str]]:
        errors = []
        valid_condition_keys = {"trust_score_below", "trust_score_above", "trust_level_in",
                               "device_age_below_days", "device_verified", "behavioral_anomaly_score_above",
                               "location_risk_above", "all_users"}
        for key in conditions.keys():
            if key not in valid_condition_keys:
                errors.append(f"Unknown condition key: {key}")
        return len(errors) == 0, errors

    def get_engine_stats(self) -> Dict[str, Any]:
        policies = self.store.get_all_policies()
        return {"total_policies": len(policies), "enabled_policies": len(self.store.get_enabled_policies()),
                "evaluations": self.evaluation_count,
                "average_evaluation_time_ms": self.total_evaluation_time / self.evaluation_count if self.evaluation_count > 0 else 0,
                "store_stats": self.store.get_stats()}

    def reset_stats(self):
        self.evaluation_count = 0
        self.total_evaluation_time = 0.0