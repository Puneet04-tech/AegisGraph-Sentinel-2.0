"""
Policy Decision Engine for AI-driven policy enforcement.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    AdaptivePolicy,
    ControlRule,
    RiskLevel,
    MitigationAction,
    TransactionAssessment,
    PolicyChange,
)


class PolicyDecisionEngine:
    """
    Provides AI-driven policy decision making.

    Handles:
    - Policy evaluation
    - Rule matching
    - Policy enforcement
    - Policy adjustment
    """

    def __init__(self):
        self._policy_cache: Dict[str, AdaptivePolicy] = {}
        self._rule_cache: Dict[str, ControlRule] = {}

    async def evaluate_policies(
        self,
        assessment: TransactionAssessment,
        active_policies: List[AdaptivePolicy],
    ) -> Dict[str, Any]:
        """Evaluate applicable policies for a transaction."""
        applicable_policies = []
        triggered_rules = []
        recommended_actions = []

        for policy in active_policies:
            if self._is_policy_applicable(policy, assessment):
                applicable_policies.append(policy)

                if assessment.risk_score >= policy.risk_threshold:
                    triggered_rules.extend(policy.control_actions)
                    recommended_actions.extend(policy.control_actions)

        return {
            "applicable_policies": [p.policy_id for p in applicable_policies],
            "triggered_rules": [a.value for a in triggered_rules[:5]],
            "recommended_actions": list(set([a.value for a in recommended_actions[:5]])),
            "requires_escalation": assessment.risk_score >= 0.8,
        }

    def _is_policy_applicable(
        self,
        policy: AdaptivePolicy,
        assessment: TransactionAssessment,
    ) -> bool:
        """Check if policy is applicable to assessment."""
        conditions = policy.conditions

        # Check entity type
        if "entity_type" in conditions:
            if conditions["entity_type"] != assessment.risk_level.value:
                return False

        # Check transaction amount range
        if "min_amount" in conditions:
            if assessment.amount_score < conditions["min_amount"]:
                return False
        if "max_amount" in conditions:
            if assessment.amount_score > conditions["max_amount"]:
                return False

        # Check time window
        if "time_window" in conditions:
            # Time window check would go here
            pass

        return True

    async def match_control_rules(
        self,
        assessment: TransactionAssessment,
        active_rules: List[ControlRule],
    ) -> List[ControlRule]:
        """Match applicable control rules."""
        matched_rules = []

        for rule in active_rules:
            if self._match_rule_conditions(rule, assessment):
                if assessment.risk_score >= rule.risk_threshold:
                    matched_rules.append(rule)

        # Sort by priority
        matched_rules.sort(key=lambda r: r.priority, reverse=True)

        return matched_rules[:10]  # Limit to top 10 rules

    def _match_rule_conditions(
        self,
        rule: ControlRule,
        assessment: TransactionAssessment,
    ) -> bool:
        """Check if rule conditions match assessment."""
        conditions = rule.conditions

        # Check rule type
        if "rule_type" in conditions:
            if conditions["rule_type"] not in assessment.risk_factors:
                return False

        # Check specific indicators
        if "indicators" in conditions:
            matching = any(
                ind in assessment.indicators
                for ind in conditions["indicators"]
            )
            if not matching:
                return False

        # Check velocity threshold
        if "velocity_threshold" in conditions:
            if assessment.velocity_score < conditions["velocity_threshold"]:
                return False

        return True

    async def adjust_policy(
        self,
        policy: AdaptivePolicy,
        feedback: Dict[str, Any],
    ) -> AdaptivePolicy:
        """Adjust policy based on feedback."""
        # Update risk threshold
        if "risk_threshold_adjustment" in feedback:
            policy.risk_threshold = max(
                0.1, min(1.0, policy.risk_threshold + feedback["risk_threshold_adjustment"])
            )

        # Update success rate
        if "success_rate" in feedback:
            alpha = 0.1
            policy.success_rate = (
                alpha * feedback["success_rate"] +
                (1 - alpha) * policy.success_rate
            )

        # Update trigger count
        policy.trigger_count += 1
        policy.last_triggered = datetime.now(timezone.utc)

        return policy

    async def create_policy(
        self,
        name: str,
        description: str,
        risk_threshold: float,
        control_actions: List[MitigationAction],
        conditions: Optional[Dict[str, Any]] = None,
    ) -> AdaptivePolicy:
        """Create a new adaptive policy."""
        policy = AdaptivePolicy(
            policy_id=str(uuid.uuid4()),
            name=name,
            description=description,
            risk_threshold=risk_threshold,
            control_actions=control_actions,
            conditions=conditions or {},
        )

        self._policy_cache[policy.policy_id] = policy
        return policy

    async def create_control_rule(
        self,
        name: str,
        rule_type: str,
        conditions: Dict[str, Any],
        action: MitigationAction,
        risk_threshold: float = 0.7,
    ) -> ControlRule:
        """Create a new control rule."""
        rule = ControlRule(
            rule_id=str(uuid.uuid4()),
            name=name,
            rule_type=rule_type,
            conditions=conditions,
            action=action,
            risk_threshold=risk_threshold,
        )

        self._rule_cache[rule.rule_id] = rule
        return rule

    def record_policy_change(
        self,
        policy_id: str,
        change_type: str,
        old_value: Dict[str, Any],
        new_value: Dict[str, Any],
        reason: str,
        changed_by: str,
    ) -> PolicyChange:
        """Record a policy change."""
        change = PolicyChange(
            change_id=str(uuid.uuid4()),
            policy_id=policy_id,
            change_type=change_type,
            old_value=old_value,
            new_value=new_value,
            reason=reason,
            changed_by=changed_by,
        )

        return change

    async def get_policy_recommendations(
        self,
        risk_level: RiskLevel,
        recent_assessments: List[TransactionAssessment],
    ) -> List[Dict[str, Any]]:
        """Get policy recommendations based on risk patterns."""
        recommendations = []

        # Analyze recent assessments
        if not recent_assessments:
            return recommendations

        # Find common patterns
        common_factors = self._find_common_factors(recent_assessments)

        if common_factors:
            recommendations.append({
                "type": "new_policy",
                "description": f"Create policy for {common_factors[0]} pattern",
                "priority": "high",
                "expected_impact": 0.2,
            })

        # Check for threshold adjustments
        avg_risk = sum(a.risk_score for a in recent_assessments) / len(recent_assessments)
        if avg_risk > 0.6:
            recommendations.append({
                "type": "threshold_adjustment",
                "description": "Consider tightening risk thresholds",
                "priority": "medium",
                "expected_impact": 0.15,
            })

        return recommendations

    def _find_common_factors(
        self,
        assessments: List[TransactionAssessment],
    ) -> List[str]:
        """Find common risk factors across assessments."""
        factor_counts: Dict[str, int] = {}

        for assessment in assessments:
            for factor in assessment.risk_factors:
                factor_counts[factor] = factor_counts.get(factor, 0) + 1

        # Return factors appearing in > 50% of assessments
        threshold = len(assessments) * 0.5
        return [f for f, count in factor_counts.items() if count >= threshold]


# Global engine instance
_engine: Optional[PolicyDecisionEngine] = None


def get_policy_engine() -> PolicyDecisionEngine:
    """Get the policy decision engine instance."""
    global _engine
    if _engine is None:
        _engine = PolicyDecisionEngine()
    return _engine