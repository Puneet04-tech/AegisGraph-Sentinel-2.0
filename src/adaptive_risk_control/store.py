"""
Storage layer for Adaptive Risk Control Platform.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    RiskProfile,
    RiskDecision,
    FraudAttempt,
    AdaptivePolicy,
    ControlRule,
    TransactionAssessment,
    RiskLevel,
    ThreatIndicator,
    LearningFeedback,
    AuditRecord,
)


class LRUCache(OrderedDict):
    """Thread-safe LRU cache."""

    def __init__(self, maxsize: int = 10000, *args, **kwds):
        self.maxsize = maxsize
        super().__init__(*args, **kwds)
        self._lock = threading.RLock()

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            value = super().__getitem__(key)
            self.move_to_end(key)
            return value

    def __setitem__(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self:
                self.move_to_end(key)
            super().__setitem__(key, value)
            if len(self) > self.maxsize:
                oldest = next(iter(self))
                del self[oldest]

    def __delitem__(self, key: str) -> None:
        with self._lock:
            super().__delitem__(key)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return super().__contains__(key)

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            try:
                return self[key]
            except KeyError:
                return default

    def clear(self) -> None:
        with self._lock:
            super().clear()


class AdaptiveRiskStore:
    """
    Central storage for adaptive risk control with O(1) lookup.
    """

    def __init__(
        self,
        max_profiles: int = 100000,
        max_decisions: int = 1000000,
        max_assessments: int = 500000,
    ):
        # Core storage
        self._profiles: LRUCache = LRUCache(maxsize=max_profiles)
        self._decisions: LRUCache = LRUCache(maxsize=max_decisions)
        self._assessments: LRUCache = LRUCache(maxsize=max_assessments)
        self._fraud_attempts: Dict[str, List] = {}
        self._policies: Dict[str, AdaptivePolicy] = {}
        self._control_rules: Dict[str, ControlRule] = {}
        self._audit_records: List = []
        self._threat_indicators: Dict[str, List] = {}
        self._learning_feedback: List = []

        # Index structures
        self._profiles_by_entity: Dict[str, str] = {}
        self._decisions_by_entity: Dict[str, List[str]] = {}
        self._decisions_by_status: Dict[str, List[str]] = {}
        self._assessments_by_transaction: Dict[str, str] = {}

        self._lock = threading.RLock()

    # Risk Profile Management
    def store_profile(self, profile: RiskProfile) -> None:
        """Store risk profile."""
        with self._lock:
            self._profiles[profile.profile_id] = profile
            self._profiles_by_entity[profile.entity_id] = profile.profile_id

    def get_profile(self, profile_id: str) -> Optional[RiskProfile]:
        """Get profile by ID with O(1) lookup."""
        return self._profiles.get(profile_id)

    def get_profile_by_entity(self, entity_id: str) -> Optional[RiskProfile]:
        """Get profile by entity ID."""
        profile_id = self._profiles_by_entity.get(entity_id)
        if profile_id:
            return self._profiles.get(profile_id)
        return None

    def update_profile_risk(self, entity_id: str, risk_score: float, risk_level: RiskLevel) -> bool:
        """Update entity risk profile."""
        profile = self.get_profile_by_entity(entity_id)
        if not profile:
            return False

        profile.risk_score = risk_score
        profile.risk_level = risk_level
        profile.last_evaluation = datetime.now(timezone.utc)
        self.store_profile(profile)
        return True

    # Risk Decision Management
    def store_decision(self, decision: RiskDecision) -> None:
        """Store risk decision."""
        with self._lock:
            self._decisions[decision.decision_id] = decision

            # Update indexes
            if decision.entity_id not in self._decisions_by_entity:
                self._decisions_by_entity[decision.entity_id] = []
            self._decisions_by_entity[decision.entity_id].append(decision.decision_id)

            status = "pending" if decision.requires_review else decision.decision_type.value
            if status not in self._decisions_by_status:
                self._decisions_by_status[status] = []
            self._decisions_by_status[status].append(decision.decision_id)

    def get_decision(self, decision_id: str) -> Optional[RiskDecision]:
        """Get decision by ID."""
        return self._decisions.get(decision_id)

    def get_decisions_for_entity(
        self, entity_id: str, limit: int = 100
    ) -> List[RiskDecision]:
        """Get all decisions for an entity."""
        decision_ids = self._decisions_by_entity.get(entity_id, [])[-limit:]
        return [
            self._decisions[did]
            for did in decision_ids
            if did in self._decisions
        ]

    def get_pending_decisions(self, limit: int = 100) -> List[RiskDecision]:
        """Get pending review decisions."""
        decision_ids = self._decisions_by_status.get("pending", [])[-limit:]
        return [
            self._decisions[did]
            for did in decision_ids
            if did in self._decisions
        ]

    # Transaction Assessment Management
    def store_assessment(self, assessment: TransactionAssessment) -> None:
        """Store transaction assessment."""
        with self._lock:
            self._assessments[assessment.assessment_id] = assessment
            self._assessments_by_transaction[assessment.transaction_id] = assessment.assessment_id

    def get_assessment(self, assessment_id: str) -> Optional[TransactionAssessment]:
        """Get assessment by ID."""
        return self._assessments.get(assessment_id)

    def get_assessment_by_transaction(self, transaction_id: str) -> Optional[TransactionAssessment]:
        """Get assessment by transaction ID."""
        assessment_id = self._assessments_by_transaction.get(transaction_id)
        if assessment_id:
            return self._assessments.get(assessment_id)
        return None

    # Fraud Attempt Management
    def store_fraud_attempt(self, attempt: FraudAttempt) -> None:
        """Store detected fraud attempt."""
        with self._lock:
            if attempt.entity_id not in self._fraud_attempts:
                self._fraud_attempts[attempt.entity_id] = []
            self._fraud_attempts[attempt.entity_id].append(attempt)

    def get_fraud_attempts(
        self, entity_id: str, limit: int = 100
    ) -> List[FraudAttempt]:
        """Get fraud attempts for an entity."""
        attempts = self._fraud_attempts.get(entity_id, [])[-limit:]
        return attempts

    def get_recent_fraud_attempts(self, hours: int = 24, limit: int = 100) -> List[FraudAttempt]:
        """Get recent fraud attempts."""
        cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)
        all_attempts = []

        for attempts in self._fraud_attempts.values():
            for attempt in attempts:
                if attempt.detected_at.timestamp() >= cutoff:
                    all_attempts.append(attempt)

        all_attempts.sort(key=lambda a: a.detected_at, reverse=True)
        return all_attempts[:limit]

    # Policy Management
    def store_policy(self, policy: AdaptivePolicy) -> None:
        """Store adaptive policy."""
        with self._lock:
            self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> Optional[AdaptivePolicy]:
        """Get policy by ID."""
        return self._policies.get(policy_id)

    def get_active_policies(self) -> List[AdaptivePolicy]:
        """Get all active policies."""
        return [p for p in self._policies.values() if p.is_active]

    def get_policies_by_risk_threshold(self, threshold: float) -> List[AdaptivePolicy]:
        """Get policies applicable to a risk threshold."""
        return [
            p for p in self._policies.values()
            if p.is_active and p.risk_threshold <= threshold
        ]

    # Control Rule Management
    def store_control_rule(self, rule: ControlRule) -> None:
        """Store control rule."""
        with self._lock:
            self._control_rules[rule.rule_id] = rule

    def get_control_rule(self, rule_id: str) -> Optional[ControlRule]:
        """Get control rule by ID."""
        return self._control_rules.get(rule_id)

    def get_active_rules(self) -> List[ControlRule]:
        """Get all active control rules."""
        return [r for r in self._control_rules.values() if r.is_active]

    def get_rules_for_risk_level(self, risk_level: RiskLevel) -> List[ControlRule]:
        """Get rules for a specific risk level."""
        threshold = self._risk_level_to_threshold(risk_level)
        return [
            r for r in self._control_rules.values()
            if r.is_active and r.risk_threshold <= threshold
        ]

    # Threat Indicator Management
    def store_threat_indicator(self, indicator: ThreatIndicator) -> None:
        """Store threat indicator."""
        with self._lock:
            if indicator.indicator_type not in self._threat_indicators:
                self._threat_indicators[indicator.indicator_type] = []
            self._threat_indicators[indicator.indicator_type].append(indicator)

    def get_threat_indicators(
        self, indicator_type: Optional[str] = None, active_only: bool = True
    ) -> List[ThreatIndicator]:
        """Get threat indicators."""
        if indicator_type:
            indicators = self._threat_indicators.get(indicator_type, [])
        else:
            indicators = []
            for ind_list in self._threat_indicators.values():
                indicators.extend(ind_list)

        if active_only:
            indicators = [i for i in indicators if i.is_active]

        return indicators

    # Learning Feedback Management
    def store_learning_feedback(self, feedback: LearningFeedback) -> None:
        """Store learning feedback."""
        with self._lock:
            self._learning_feedback.append(feedback)
            # Keep last 10000 feedback items
            if len(self._learning_feedback) > 10000:
                self._learning_feedback = self._learning_feedback[-10000:]

    def get_unprocessed_feedback(self, limit: int = 100) -> List[LearningFeedback]:
        """Get unprocessed learning feedback."""
        return [
            f for f in self._learning_feedback[-limit:]
            if not f.is_processed
        ]

    # Audit Management
    def store_audit_record(self, record: AuditRecord) -> None:
        """Store audit record."""
        with self._lock:
            self._audit_records.append(record)
            if len(self._audit_records) > 50000:
                self._audit_records = self._audit_records[-50000:]

    def get_audit_records(
        self,
        entity_id: Optional[str] = None,
        operation: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditRecord]:
        """Query audit records."""
        result = []
        for record in reversed(self._audit_records):
            if entity_id and record.entity_id != entity_id:
                continue
            if operation and record.operation != operation:
                continue
            result.append(record)
            if len(result) >= limit:
                break
        return result

    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        recent_fraud = self.get_recent_fraud_attempts(hours=24)
        prevented_fraud = sum(1 for f in recent_fraud if f.prevented)

        return {
            "total_profiles": len(self._profiles),
            "total_decisions": len(self._decisions),
            "total_assessments": len(self._assessments),
            "fraud_attempts_24h": len(recent_fraud),
            "fraud_prevented_24h": prevented_fraud,
            "active_policies": len(self.get_active_policies()),
            "active_rules": len(self.get_active_rules()),
            "pending_reviews": len(self.get_pending_decisions()),
            "by_decision_type": self._count_by_decision_type(),
            "by_risk_level": self._count_by_risk_level(),
        }

    def _count_by_decision_type(self) -> Dict[str, int]:
        """Count decisions by type."""
        counts: Dict[str, int] = {}
        for decision in self._decisions.values():
            dtype = decision.decision_type.value
            counts[dtype] = counts.get(dtype, 0) + 1
        return counts

    def _count_by_risk_level(self) -> Dict[str, int]:
        """Count profiles by risk level."""
        counts: Dict[str, int] = {}
        for profile in self._profiles.values():
            rlevel = profile.risk_level.value
            counts[rlevel] = counts.get(rlevel, 0) + 1
        return counts

    def _risk_level_to_threshold(self, risk_level: RiskLevel) -> float:
        """Convert risk level to threshold."""
        thresholds = {
            RiskLevel.MINIMAL: 0.1,
            RiskLevel.LOW: 0.3,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.7,
            RiskLevel.CRITICAL: 0.9,
        }
        return thresholds.get(risk_level, 0.5)


# Global store instance
_store: Optional[AdaptiveRiskStore] = None


def get_adaptive_risk_store() -> AdaptiveRiskStore:
    """Get the adaptive risk store instance."""
    global _store
    if _store is None:
        _store = AdaptiveRiskStore()
    return _store


def reset_store() -> None:
    """Reset the store (for testing)."""
    global _store
    _store = None