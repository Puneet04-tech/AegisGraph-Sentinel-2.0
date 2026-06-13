"""
Main Service for Autonomous Fraud Prevention & Adaptive Risk Control Platform.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from .models import (
    RiskProfile,
    MitigationAction,
    AuditRecord,
)
from .store import AdaptiveRiskStore, get_adaptive_risk_store
from .risk_engine import get_risk_engine
from .prevention_engine import get_prevention_engine
from .policy_engine import get_policy_engine
from .control_manager import get_control_manager
from .mitigation_engine import get_mitigation_engine
from .recommendation_engine import get_recommendation_engine
from .adaptive_learning import get_learning_engine


class AdaptiveRiskConfig:
    """Configuration for adaptive risk control service."""
    auto_block_threshold: float = 0.9
    challenge_threshold: float = 0.7
    monitor_threshold: float = 0.5
    learning_rate: float = 0.1
    max_velocity: int = 10


class AdaptiveRiskControlService:
    """
    Main orchestrator for autonomous fraud prevention.

    Integrates all components:
    - Adaptive Risk Engine
    - Fraud Prevention Engine
    - Policy Decision Engine
    - Dynamic Control Manager
    - Real-Time Mitigation Engine
    - Policy Recommendation Engine
    - Adaptive Learning Engine
    """

    def __init__(
        self,
        store: Optional[AdaptiveRiskStore] = None,
        config: Optional[AdaptiveRiskConfig] = None,
    ):
        self._store = store or get_adaptive_risk_store()
        self._config = config or AdaptiveRiskConfig()

        # Initialize engines
        self._risk_engine = get_risk_engine()
        self._prevention = get_prevention_engine()
        self._policy = get_policy_engine()
        self._controls = get_control_manager()
        self._mitigation = get_mitigation_engine()
        self._recommendations = get_recommendation_engine()
        self._learning = get_learning_engine()

    # Risk Evaluation
    async def evaluate_risk(
        self,
        entity_id: str,
        transaction_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate transaction risk in real-time."""
        # Get existing profile
        profile = self._store.get_profile_by_entity(entity_id)

        # Evaluate risk
        assessment = await self._risk_engine.evaluate_risk(
            entity_id=entity_id,
            transaction_data=transaction_data,
            profile=profile,
        )

        # Store assessment
        self._store.store_assessment(assessment)

        # Update profile
        if profile:
            profile = await self._risk_engine.update_risk_profile(profile, assessment)
            self._store.store_profile(profile)
        else:
            # Create new profile
            new_profile = RiskProfile(
                profile_id=str(uuid.uuid4()),
                entity_id=entity_id,
                entity_type=transaction_data.get("entity_type", "unknown"),
                risk_score=assessment.risk_score,
                risk_level=assessment.risk_level,
                trust_score=1.0 - assessment.risk_score,
            )
            self._store.store_profile(new_profile)

        # Log operation
        self._log_operation("risk_evaluate", entity_id, {
            "transaction_id": assessment.transaction_id,
            "risk_score": assessment.risk_score,
            "decision": assessment.decision.value,
        })

        return {
            "assessment_id": assessment.assessment_id,
            "transaction_id": assessment.transaction_id,
            "risk_score": assessment.risk_score,
            "risk_level": assessment.risk_level.value,
            "decision": assessment.decision.value,
            "confidence": assessment.confidence,
            "processing_time_ms": assessment.processing_time_ms,
            "risk_factors": assessment.risk_factors,
            "indicators": assessment.indicators,
        }

    # Fraud Prevention
    async def prevent_fraud(
        self,
        assessment_id: str,
    ) -> Dict[str, Any]:
        """Execute fraud prevention actions."""
        assessment = self._store.get_assessment(assessment_id)
        if not assessment:
            return {"error": "Assessment not found"}

        # Execute prevention
        prevention_result = await self._prevention.prevent_fraud(assessment)

        # Record fraud attempt if high risk
        if assessment.risk_score >= 0.7:
            attempt = await self._prevention.record_fraud_attempt(
                entity_id=assessment.entity_id,
                assessment=assessment,
                prevented=prevention_result.get("prevented", False),
            )
            self._store.store_fraud_attempt(attempt)

            # Execute mitigation
            if prevention_result.get("prevented"):
                for action in prevention_result.get("actions_taken", []):
                    await self._mitigation.execute_mitigation(
                        assessment,
                        MitigationAction(action) if action in [a.value for a in MitigationAction] else MitigationAction.BLOCK,
                    )

        self._log_operation("fraud_prevent", assessment.entity_id, {
            "assessment_id": assessment_id,
            "prevented": prevention_result.get("prevented"),
        })

        return prevention_result

    # Control Management
    async def apply_control(
        self,
        rule_id: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Apply a control rule."""
        rule = self._store.get_control_rule(rule_id)
        if not rule:
            return {"error": "Control rule not found"}

        # Trigger control
        result = await self._controls.trigger_control(rule_id, context)

        self._log_operation("control_apply", context.get("entity_id"), {
            "rule_id": rule_id,
            "action": rule.action.value,
        })

        return result

    # Mitigation
    async def mitigate(
        self,
        assessment_id: str,
        action: str,
    ) -> Dict[str, Any]:
        """Execute mitigation action."""
        assessment = self._store.get_assessment(assessment_id)
        if not assessment:
            return {"error": "Assessment not found"}

        # Execute mitigation
        result = await self._mitigation.execute_mitigation(
            assessment,
            MitigationAction(action) if action in [a.value for a in MitigationAction] else MitigationAction.FLAG,
        )

        self._log_operation("mitigate", assessment.entity_id, {
            "assessment_id": assessment_id,
            "action": action,
            "mitigation_id": result.get("mitigation_id"),
        })

        return result

    # Policy Management
    async def get_policies(self) -> List[Dict[str, Any]]:
        """Get all active policies."""
        policies = self._store.get_active_policies()

        return [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "description": p.description,
                "risk_threshold": p.risk_threshold,
                "control_actions": [a.value for a in p.control_actions],
                "trigger_count": p.trigger_count,
                "success_rate": p.success_rate,
            }
            for p in policies
        ]

    async def create_policy(
        self,
        name: str,
        description: str,
        risk_threshold: float,
        control_actions: List[str],
    ) -> Dict[str, Any]:
        """Create a new policy."""
        policy = await self._policy.create_policy(
            name=name,
            description=description,
            risk_threshold=risk_threshold,
            control_actions=[MitigationAction(a) for a in control_actions],
        )

        self._store.store_policy(policy)

        self._log_operation("policy_create", None, {
            "policy_id": policy.policy_id,
            "name": name,
        })

        return {
            "policy_id": policy.policy_id,
            "name": policy.name,
            "risk_threshold": policy.risk_threshold,
        }

    # Risk Profile
    async def get_risk_profile(self, entity_id: str) -> Dict[str, Any]:
        """Get risk profile for an entity."""
        profile = self._store.get_profile_by_entity(entity_id)

        if not profile:
            return {"error": "Profile not found"}

        return {
            "profile_id": profile.profile_id,
            "entity_id": profile.entity_id,
            "risk_score": profile.risk_score,
            "risk_level": profile.risk_level.value,
            "trust_score": profile.trust_score,
            "last_evaluation": profile.last_evaluation.isoformat(),
            "risk_factors": profile.risk_factors,
            "risk_trend": profile.risk_trend,
            "total_transactions": profile.total_transactions,
            "fraudulent_transactions": profile.fraudulent_transactions,
        }

    # Recommendations
    async def get_recommendations(self, entity_id: str) -> List[Dict[str, Any]]:
        """Get risk recommendations for an entity."""
        # Get recent assessments
        decisions = self._store.get_decisions_for_entity(entity_id, limit=100)
        assessments = [
            self._store.get_assessment(d.decision_id)
            for d in decisions
        ]
        assessments = [a for a in assessments if a]

        # Generate recommendations
        recommendations = await self._recommendations.generate_recommendations(
            entity_id=entity_id,
            recent_assessments=assessments,
        )

        return [
            {
                "recommendation_id": r.recommendation_id,
                "type": r.recommendation_type,
                "description": r.description,
                "priority": r.priority,
                "actions": r.actions,
                "expected_impact": r.expected_impact,
            }
            for r in recommendations
        ]

    # Dashboard
    async def get_dashboard(self) -> Dict[str, Any]:
        """Get risk control dashboard."""
        stats = self._store.get_stats()
        active_controls = await self._controls.get_active_controls()
        learning_stats = await self._learning.get_learning_stats()

        return {
            "risk_stats": stats,
            "active_controls": len(active_controls),
            "prevention_enabled": True,
            "learning_stats": learning_stats,
            "recent_fraud_attempts": stats.get("fraud_attempts_24h", 0),
            "fraud_prevented": stats.get("fraud_prevented_24h", 0),
        }

    # Audit
    async def get_audit_records(
        self,
        entity_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit records."""
        records = self._store.get_audit_records(entity_id=entity_id, limit=limit)

        return [
            {
                "record_id": r.record_id,
                "operation": r.operation,
                "entity_id": r.entity_id,
                "user_id": r.user_id,
                "action": r.action,
                "timestamp": r.timestamp.isoformat(),
                "success": r.success,
            }
            for r in records
        ]

    # Feedback
    async def submit_feedback(
        self,
        entity_id: str,
        transaction_id: str,
        feedback_type: str,
        actual_outcome: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Submit learning feedback."""
        from .models import LearningFeedback, LearningFeedbackType

        # Get original assessment
        assessment = self._store.get_assessment_by_transaction(transaction_id)

        feedback = LearningFeedback(
            feedback_id=str(uuid.uuid4()),
            entity_id=entity_id,
            transaction_id=transaction_id,
            feedback_type=LearningFeedbackType(feedback_type),
            risk_score_predicted=assessment.risk_score if assessment else 0.5,
            risk_score_actual=actual_outcome.get("risk_score", 0.5),
            features={},
            model_version="1.0.0",
        )

        # Process feedback
        result = await self._learning.process_feedback(feedback)

        self._log_operation("feedback_submit", entity_id, {
            "feedback_id": feedback.feedback_id,
            "type": feedback_type,
        })

        return result

    def _log_operation(
        self,
        operation: str,
        entity_id: Optional[str],
        details: Dict[str, Any],
    ) -> None:
        """Log operation for audit."""
        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            operation=operation,
            entity_id=entity_id,
            transaction_id=details.get("transaction_id"),
            user_id="system",
            action=operation,
            details=details,
        )
        self._store.store_audit_record(record)


# Global service instance
_service: Optional[AdaptiveRiskControlService] = None


def get_prevention_service() -> AdaptiveRiskControlService:
    """Get the prevention service instance."""
    global _service
    if _service is None:
        _service = AdaptiveRiskControlService()
    return _service