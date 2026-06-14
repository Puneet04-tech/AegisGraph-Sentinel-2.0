"""
Policy Engine for Adaptive Authentication & Continuous Authorization.

Manages authorization policies and evaluates access decisions based on
trust levels, risk scores, and contextual factors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from .models import (
    AuthenticationSession,
    AuthorizationPolicy,
    PolicyAction,
    RiskLevel,
    RiskScore,
    TrustLevel,
)
from .store import AdaptiveAuthStore, get_adaptive_auth_store


@dataclass
class PolicyEvaluationContext:
    """Context for policy evaluation."""
    session: AuthenticationSession
    resource: str
    action: str
    risk_score: Optional[RiskScore]
    trust_level: TrustLevel
    user_id: str
    ip_address: str
    user_agent: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    policy_id: str
    policy_name: str
    action: PolicyAction
    allowed: bool
    requires_step_up: bool
    step_up_challenge_types: List[str] = field(default_factory=list)
    denied_reason: Optional[str] = None
    matched_conditions: Dict[str, Any] = field(default_factory=dict)
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AccessDecision:
    """Final access decision combining all policy evaluations."""
    resource: str
    action: str
    allowed: bool
    decisions: List[PolicyDecision]
    final_action: PolicyAction
    step_up_required: bool
    step_up_challenge_types: List[str] = field(default_factory=list)
    trust_level_required: TrustLevel = TrustLevel.LOW
    risk_level_maximum: RiskLevel = RiskLevel.HIGH
    denied_reason: Optional[str] = None
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyEvaluator:
    """Evaluates policies against access requests."""
    
    def __init__(self, store: AdaptiveAuthStore):
        self.store = store
        self._cache: Dict[str, PolicyDecision] = {}
        self._cache_ttl = 60  # seconds
    
    def evaluate_policy(
        self,
        policy: AuthorizationPolicy,
        context: PolicyEvaluationContext,
    ) -> PolicyDecision:
        """Evaluate a single policy against the context."""
        # Check if resource matches policy pattern
        if not self._resource_matches(policy.resource_pattern, context.resource):
            return PolicyDecision(
                policy_id=policy.policy_id,
                policy_name=policy.name,
                action=PolicyAction.ALLOW,
                allowed=True,
                requires_step_up=False,
                matched_conditions={},
            )
        
        # Check conditions
        conditions_met, matched = self._evaluate_conditions(policy.conditions, context)
        if not conditions_met:
            return PolicyDecision(
                policy_id=policy.policy_id,
                policy_name=policy.name,
                action=PolicyAction.ALLOW,
                allowed=True,
                requires_step_up=False,
                matched_conditions=matched,
            )
        
        # Check trust level requirement
        if not self._trust_level_sufficient(context.trust_level, policy.required_trust_level):
            return PolicyDecision(
                policy_id=policy.policy_id,
                policy_name=policy.name,
                action=policy.action_on_violation,
                allowed=False,
                requires_step_up=policy.step_up_required,
                step_up_challenge_types=[ct.value for ct in policy.step_up_challenge_types],
                denied_reason=f"Trust level {context.trust_level.value} insufficient (required: {policy.required_trust_level.value})",
                matched_conditions=matched,
            )
        
        # Check risk level requirement
        if context.risk_score and not self._risk_level_acceptable(context.risk_score.risk_level, policy.required_risk_level):
            return PolicyDecision(
                policy_id=policy.policy_id,
                policy_name=policy.name,
                action=policy.action_on_violation,
                allowed=False,
                requires_step_up=policy.step_up_required,
                step_up_challenge_types=[ct.value for ct in policy.step_up_challenge_types],
                denied_reason=f"Risk level {context.risk_score.risk_level.value} too high (max: {policy.required_risk_level.value})",
                matched_conditions=matched,
            )
        
        # Check auth method restrictions
        if policy.allowed_auth_methods:
            session_auth_methods = context.session.metadata.get("auth_methods", [])
            if not any(m in policy.allowed_auth_methods for m in session_auth_methods):
                return PolicyDecision(
                    policy_id=policy.policy_id,
                    policy_name=policy.name,
                    action=policy.action_on_violation,
                    allowed=False,
                    requires_step_up=policy.step_up_required,
                    step_up_challenge_types=[ct.value for ct in policy.step_up_challenge_types],
                    denied_reason="Authentication method not allowed for this resource",
                    matched_conditions=matched,
                )
        
        # All checks passed
        return PolicyDecision(
            policy_id=policy.policy_id,
            policy_name=policy.name,
            action=PolicyAction.ALLOW,
            allowed=True,
            requires_step_up=False,
            matched_conditions=matched,
        )
    
    def _resource_matches(self, pattern: str, resource: str) -> bool:
        """Check if resource matches policy pattern."""
        try:
            return bool(re.match(pattern, resource))
        except re.error:
            return resource == pattern
    
    def _evaluate_conditions(
        self,
        conditions: Dict[str, Any],
        context: PolicyEvaluationContext,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Evaluate policy conditions."""
        if not conditions:
            return True, {}
        
        matched = {}
        all_passed = True
        
        # Time-based conditions
        if "allowed_hours" in conditions:
            current_hour = context.timestamp.hour
            allowed = conditions["allowed_hours"]
            if isinstance(allowed, list) and len(allowed) == 2:
                start, end = allowed
                if start <= end:
                    in_range = start <= current_hour < end
                else:  # Handles overnight ranges like 22-06
                    in_range = current_hour >= start or current_hour < end
                
                matched["allowed_hours"] = in_range
                if not in_range:
                    all_passed = False
        
        # Day-based conditions
        if "allowed_days" in conditions:
            current_day = context.timestamp.strftime("%A").lower()
            allowed_days = [d.lower() for d in conditions["allowed_days"]]
            matched["allowed_days"] = current_day in allowed_days
            if current_day not in allowed_days:
                all_passed = False
        
        # IP-based conditions
        if "allowed_ip_ranges" in conditions:
            ip = context.ip_address
            ranges = conditions["allowed_ip_ranges"]
            matched["ip_allowed"] = any(self._ip_in_range(ip, r) for r in ranges)
            if not matched["ip_allowed"]:
                all_passed = False
        
        # User group conditions
        if "required_groups" in conditions:
            user_groups = context.context.get("user_groups", [])
            required = conditions["required_groups"]
            matched["has_required_group"] = any(g in user_groups for g in required)
            if not matched["has_required_group"]:
                all_passed = False
        
        return all_passed, matched
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in CIDR range."""
        try:
            if "/" not in ip_range:
                return ip == ip_range
            
            ip_parts = [int(p) for p in ip.split(".")]
            range_parts, bits = ip_range.split("/")
            range_ip_parts = [int(p) for p in range_parts.split(".")]
            prefix_len = int(bits)
            
            ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
            range_int = (range_ip_parts[0] << 24) + (range_ip_parts[1] << 16) + (range_ip_parts[2] << 8) + range_ip_parts[3]
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
            
            return (ip_int & mask) == (range_int & mask)
        except (ValueError, IndexError):
            return False
    
    def _trust_level_sufficient(
        self,
        actual: TrustLevel,
        required: TrustLevel,
    ) -> bool:
        """Check if trust level is sufficient."""
        trust_order = [TrustLevel.NONE, TrustLevel.LOW, TrustLevel.MEDIUM, TrustLevel.HIGH, TrustLevel.FULL]
        try:
            return trust_order.index(actual) >= trust_order.index(required)
        except ValueError:
            return False
    
    def _risk_level_acceptable(
        self,
        actual: RiskLevel,
        maximum: RiskLevel,
    ) -> bool:
        """Check if risk level is acceptable."""
        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        try:
            return risk_order.index(actual) <= risk_order.index(maximum)
        except ValueError:
            return False


class PolicyEngine:
    """
    Main policy engine for authorization decisions.
    
    Manages policies and evaluates access requests against all applicable
    policies to make authorization decisions.
    """
    
    def __init__(self, store: AdaptiveAuthStore):
        self.store = store
        self.evaluator = PolicyEvaluator(store)
        self._audit_log: List[Dict[str, Any]] = []
    
    def evaluate_access(
        self,
        session_id: str,
        resource: str,
        action: str = "access",
        context: Optional[Dict[str, Any]] = None,
    ) -> AccessDecision:
        """Evaluate access request against all applicable policies."""
        session = self.store.get_session(session_id)
        if not session:
            return AccessDecision(
                resource=resource,
                action=action,
                allowed=False,
                decisions=[],
                final_action=PolicyAction.DENY,
                step_up_required=False,
                denied_reason="Session not found or expired",
            )
        
        # Build evaluation context
        eval_context = PolicyEvaluationContext(
            session=session,
            resource=resource,
            action=action,
            risk_score=session.current_risk_score,
            trust_level=session.trust.trust_level,
            user_id=session.user_id,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            context=context or {},
        )
        
        # Get applicable policies
        policies = self.store.get_enabled_policies()
        
        # Evaluate each policy
        decisions = []
        for policy in policies:
            decision = self.evaluator.evaluate_policy(policy, eval_context)
            decisions.append(decision)
        
        # Combine decisions
        return self._combine_decisions(resource, action, decisions)
    
    def _combine_decisions(
        self,
        resource: str,
        action: str,
        decisions: List[PolicyDecision],
    ) -> AccessDecision:
        """Combine individual policy decisions into final access decision."""
        # Filter to only relevant decisions (those that matched the resource)
        relevant = [d for d in decisions if d.allowed or d.denied_reason]
        
        if not relevant:
            # No matching policies, default allow
            return AccessDecision(
                resource=resource,
                action=action,
                allowed=True,
                decisions=decisions,
                final_action=PolicyAction.ALLOW,
                step_up_required=False,
            )
        
        # Check for any deny decisions
        deny_decisions = [d for d in relevant if not d.allowed]
        if deny_decisions:
            most_restrictive = max(deny_decisions, key=lambda d: d.action.value)
            
            # Check if step-up could satisfy
            step_up_types = []
            for d in deny_decisions:
                if d.requires_step_up:
                    step_up_types.extend(d.step_up_challenge_types)
            
            return AccessDecision(
                resource=resource,
                action=action,
                allowed=False,
                decisions=decisions,
                final_action=most_restrictive.action,
                step_up_required=len(step_up_types) > 0,
                step_up_challenge_types=list(set(step_up_types)),
                denied_reason=most_restrictive.denied_reason,
            )
        
        # All policies allow
        step_up_decisions = [d for d in relevant if d.requires_step_up]
        step_up_types = []
        for d in step_up_decisions:
            step_up_types.extend(d.step_up_challenge_types)
        
        return AccessDecision(
            resource=resource,
            action=action,
            allowed=True,
            decisions=decisions,
            final_action=PolicyAction.ALLOW,
            step_up_required=len(step_up_types) > 0,
            step_up_challenge_types=list(set(step_up_types)),
        )
    
    def add_policy(self, policy: AuthorizationPolicy) -> str:
        """Add a new authorization policy."""
        self.store.add_policy(policy)
        return policy.policy_id
    
    def update_policy(self, policy: AuthorizationPolicy) -> bool:
        """Update an existing policy."""
        existing = self.store.get_policy(policy.policy_id)
        if not existing:
            return False
        self.store.update_policy(policy)
        return True
    
    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy."""
        return self.store.delete_policy(policy_id)
    
    def get_policies(
        self,
        enabled_only: bool = False,
    ) -> List[AuthorizationPolicy]:
        """Get authorization policies."""
        if enabled_only:
            return self.store.get_enabled_policies()
        return self.store.get_policies()
    
    def create_policy(
        self,
        name: str,
        description: str,
        resource_pattern: str,
        required_trust_level: TrustLevel = TrustLevel.LOW,
        required_risk_level: RiskLevel = RiskLevel.HIGH,
        allowed_auth_methods: Optional[List[str]] = None,
        step_up_required: bool = False,
        step_up_challenge_types: Optional[List[str]] = None,
        action_on_violation: PolicyAction = PolicyAction.DENY,
        conditions: Optional[Dict[str, Any]] = None,
        priority: int = 50,
    ) -> AuthorizationPolicy:
        """Create a new authorization policy."""
        from .models import ChallengeType
        
        policy = AuthorizationPolicy(
            policy_id=str(uuid.uuid4()),
            name=name,
            description=description,
            resource_pattern=resource_pattern,
            required_trust_level=required_trust_level,
            required_risk_level=required_risk_level,
            allowed_auth_methods=allowed_auth_methods or [],
            step_up_required=step_up_required,
            step_up_challenge_types=[
                ChallengeType(ct) for ct in (step_up_challenge_types or [])
            ],
            action_on_violation=action_on_violation,
            conditions=conditions or {},
            priority=priority,
        )
        
        self.store.add_policy(policy)
        return policy
    
    def test_policy(
        self,
        policy_id: str,
        test_context: Dict[str, Any],
    ) -> PolicyDecision:
        """Test a policy against a sample context."""
        policy = self.store.get_policy(policy_id)
        if not policy:
            raise ValueError(f"Policy {policy_id} not found")
        
        # Create a mock session for testing
        session = self.store.create_session(
            user_id=test_context.get("user_id", "test_user"),
            ip_address=test_context.get("ip_address", "192.168.1.1"),
            user_agent=test_context.get("user_agent", "TestAgent/1.0"),
        )
        
        # Set trust and risk from test context
        trust_level = test_context.get("trust_level", TrustLevel.LOW)
        if isinstance(trust_level, str):
            trust_level = TrustLevel(trust_level)
        session.trust.trust_level = trust_level
        
        context = PolicyEvaluationContext(
            session=session,
            resource=test_context.get("resource", "/api/v1/test"),
            action=test_context.get("action", "access"),
            risk_score=None,
            trust_level=trust_level,
            user_id=session.user_id,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
        )
        
        return self.evaluator.evaluate_policy(policy, context)
    
    def get_policy_stats(self) -> Dict[str, Any]:
        """Get policy engine statistics."""
        policies = self.store.get_policies()
        enabled = self.store.get_enabled_policies()
        
        return {
            "total_policies": len(policies),
            "enabled_policies": len(enabled),
            "policies_by_action": {
                "deny": sum(1 for p in policies if p.action_on_violation == PolicyAction.DENY),
                "step_up": sum(1 for p in policies if p.action_on_violation == PolicyAction.STEP_UP),
                "review": sum(1 for p in policies if p.action_on_violation == PolicyAction.REVIEW),
            },
            "policies_requiring_step_up": sum(1 for p in policies if p.step_up_required),
        }


# Global engine instance
_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> PolicyEngine:
    """Get the global policy engine instance."""
    global _engine
    if _engine is None:
        store = get_adaptive_auth_store()
        _engine = PolicyEngine(store)
    return _engine


def reset_engine() -> None:
    """Reset the engine (for testing)."""
    global _engine
    _engine = None