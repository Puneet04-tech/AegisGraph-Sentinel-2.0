"""
Real-Time Mitigation Engine for immediate threat response.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    MitigationAction,
    FraudAttempt,
    TransactionAssessment,
    RiskLevel,
)


class RealTimeMitigationEngine:
    """
    Provides immediate threat response and mitigation.

    Handles:
    - Real-time mitigation actions
    - Threat containment
    - Account protection
    - Response automation
    """

    def __init__(self):
        self._mitigation_queue: List[Dict[str, Any]] = []
        self._active_mitigations: Dict[str, Dict[str, Any]] = {}

    async def execute_mitigation(
        self,
        assessment: TransactionAssessment,
        action: MitigationAction,
    ) -> Dict[str, Any]:
        """Execute a mitigation action."""
        mitigation_id = str(uuid.uuid4())

        mitigation_result = {
            "mitigation_id": mitigation_id,
            "action": action.value,
            "transaction_id": assessment.transaction_id,
            "entity_id": assessment.entity_id,
            "status": "executed",
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }

        # Execute specific mitigation
        if action == MitigationAction.BLOCK:
            mitigation_result.update(await self._block_action(assessment))
        elif action == MitigationAction.LIMIT:
            mitigation_result.update(await self._limit_action(assessment))
        elif action == MitigationAction.FLAG:
            mitigation_result.update(await self._flag_action(assessment))
        elif action == MitigationAction.NOTIFY:
            mitigation_result.update(await self._notify_action(assessment))
        elif action == MitigationAction.ISOLATE:
            mitigation_result.update(await self._isolate_action(assessment))
        elif action == MitigationAction.FREEZE:
            mitigation_result.update(await self._freeze_action(assessment))
        elif action == MitigationAction.ESCALATE:
            mitigation_result.update(await self._escalate_action(assessment))

        # Store active mitigation
        self._active_mitigations[mitigation_id] = mitigation_result

        return mitigation_result

    async def _block_action(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Execute block action."""
        return {
            "result": "blocked",
            "message": "Transaction blocked successfully",
            "next_steps": [
                "Notify fraud team",
                "Log incident",
                "Update risk profile",
            ],
        }

    async def _limit_action(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Execute limit action."""
        return {
            "result": "limited",
            "message": "Transaction amount limited",
            "limits_applied": {
                "max_amount": assessment.amount_score * 1000,
                "max_daily": 5000,
                "max_monthly": 20000,
            },
        }

    async def _flag_action(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Execute flag action."""
        return {
            "result": "flagged",
            "message": "Transaction flagged for review",
            "flag_priority": "high" if assessment.risk_score > 0.7 else "medium",
        }

    async def _notify_action(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Execute notify action."""
        return {
            "result": "notified",
            "message": "Security notification sent",
            "notification_channels": ["email", "sms", "push"],
        }

    async def _isolate_action(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Execute isolate action."""
        return {
            "result": "isolated",
            "message": "Entity isolated from normal operations",
            "isolation_level": "enhanced_monitoring",
        }

    async def _freeze_action(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Execute freeze action."""
        return {
            "result": "frozen",
            "message": "Account temporarily frozen",
            "freeze_duration": "24 hours",
        }

    async def _escalate_action(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Execute escalate action."""
        return {
            "result": "escalated",
            "message": "Case escalated to security team",
            "escalation_priority": "urgent" if assessment.risk_level == RiskLevel.CRITICAL else "high",
        }

    async def mitigate_fraud_attempt(
        self,
        attempt: FraudAttempt,
    ) -> Dict[str, Any]:
        """Mitigate a detected fraud attempt."""
        mitigation_actions = []

        # Primary mitigation
        if attempt.risk_score >= 0.9:
            primary_action = MitigationAction.BLOCK
        elif attempt.risk_score >= 0.7:
            primary_action = MitigationAction.LIMIT
        else:
            primary_action = MitigationAction.FLAG

        result = await self.execute_mitigation(
            TransactionAssessment(
                assessment_id=str(uuid.uuid4()),
                transaction_id=attempt.affected_transactions[0] if attempt.affected_transactions else str(uuid.uuid4()),
                entity_id=attempt.entity_id,
                risk_score=attempt.risk_score,
                risk_level=self._score_to_risk_level(attempt.risk_score),
                decision=self._score_to_decision(attempt.risk_score),
                confidence=attempt.confidence,
                risk_factors=[],
                indicators=attempt.indicators,
            ),
            primary_action,
        )

        mitigation_actions.append(result)

        # Secondary mitigations
        if attempt.risk_score >= 0.8:
            notify_result = await self.execute_mitigation(
                TransactionAssessment(
                    assessment_id=str(uuid.uuid4()),
                    transaction_id=attempt.affected_transactions[0] if attempt.affected_transactions else str(uuid.uuid4()),
                    entity_id=attempt.entity_id,
                    risk_score=attempt.risk_score,
                    risk_level=self._score_to_risk_level(attempt.risk_score),
                    decision=self._score_to_decision(attempt.risk_score),
                    confidence=attempt.confidence,
                    risk_factors=[],
                    indicators=attempt.indicators,
                ),
                MitigationAction.NOTIFY,
            )
            mitigation_actions.append(notify_result)

        return {
            "attempt_id": attempt.attempt_id,
            "mitigations_applied": len(mitigation_actions),
            "actions": mitigation_actions,
            "status": "mitigated",
        }

    async def get_mitigation_status(
        self,
        mitigation_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get status of a mitigation action."""
        return self._active_mitigations.get(mitigation_id)

    async def cancel_mitigation(
        self,
        mitigation_id: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Cancel an active mitigation."""
        if mitigation_id in self._active_mitigations:
            mitigation = self._active_mitigations[mitigation_id]
            mitigation["status"] = "cancelled"
            mitigation["cancelled_at"] = datetime.now(timezone.utc).isoformat()
            mitigation["cancel_reason"] = reason

            return {
                "mitigation_id": mitigation_id,
                "status": "cancelled",
                "reason": reason,
            }

        return {"error": "Mitigation not found"}

    async def get_active_mitigations(
        self,
        entity_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get active mitigations."""
        mitigations = list(self._active_mitigations.values())

        if entity_id:
            mitigations = [
                m for m in mitigations
                if m.get("entity_id") == entity_id
            ]

        return mitigations

    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert score to risk level."""
        if score >= 0.9:
            return RiskLevel.CRITICAL
        elif score >= 0.7:
            return RiskLevel.HIGH
        elif score >= 0.5:
            return RiskLevel.MEDIUM
        elif score >= 0.3:
            return RiskLevel.LOW
        return RiskLevel.MINIMAL

    def _score_to_decision(self, score: float):
        """Convert score to decision type."""
        from .models import DecisionType
        if score >= 0.9:
            return DecisionType.BLOCK
        elif score >= 0.7:
            return DecisionType.REVIEW
        elif score >= 0.5:
            return DecisionType.CHALLENGE
        return DecisionType.APPROVE


# Global engine instance
_engine: Optional[RealTimeMitigationEngine] = None


def get_mitigation_engine() -> RealTimeMitigationEngine:
    """Get the mitigation engine instance."""
    global _engine
    if _engine is None:
        _engine = RealTimeMitigationEngine()
    return _engine