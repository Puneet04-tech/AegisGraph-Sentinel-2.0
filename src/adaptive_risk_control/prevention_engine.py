"""
Fraud Prevention Engine for real-time fraud blocking.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    FraudAttempt,
    MitigationAction,
    DecisionType,
    TransactionAssessment,
)


class FraudPreventionEngine:
    """
    Provides real-time fraud prevention and blocking.

    Handles:
    - Transaction blocking
    - Fraud escalation
    - Prevention workflow
    - Damage estimation
    """

    def __init__(self):
        self._prevention_rules = self._initialize_rules()

    def _initialize_rules(self) -> Dict[str, Any]:
        """Initialize prevention rules."""
        return {
            "auto_block_threshold": 0.9,
            "escalation_threshold": 0.8,
            "challenge_threshold": 0.7,
            "monitor_threshold": 0.5,
        }

    async def prevent_fraud(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Execute fraud prevention actions."""
        prevention_result = {
            "prevented": False,
            "actions_taken": [],
            "block_id": None,
            "escalation_required": False,
        }

        # Determine prevention actions based on decision
        if assessment.decision == DecisionType.BLOCK:
            result = await self._block_transaction(assessment)
            prevention_result.update(result)
        elif assessment.decision == DecisionType.DENY:
            result = await self._deny_transaction(assessment)
            prevention_result.update(result)
        elif assessment.decision == DecisionType.CHALLENGE:
            result = await self._challenge_transaction(assessment)
            prevention_result.update(result)
        elif assessment.decision == DecisionType.REVIEW:
            result = await self._escalate_for_review(assessment)
            prevention_result.update(result)

        return prevention_result

    async def _block_transaction(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Block a high-risk transaction."""
        block_id = str(uuid.uuid4())

        return {
            "prevented": True,
            "actions_taken": [
                MitigationAction.BLOCK.value,
                MitigationAction.NOTIFY.value,
            ],
            "block_id": block_id,
            "escalation_required": True,
            "reason": "Transaction blocked due to critical risk score",
        }

    async def _deny_transaction(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Deny a fraudulent transaction."""
        deny_id = str(uuid.uuid4())

        return {
            "prevented": True,
            "actions_taken": [
                MitigationAction.DENY.value if hasattr(MitigationAction, 'DENY') else MitigationAction.BLOCK.value,
                MitigationAction.FLAG.value,
            ],
            "deny_id": deny_id,
            "escalation_required": assessment.risk_score >= 0.95,
            "reason": "Transaction denied due to fraud indicators",
        }

    async def _challenge_transaction(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Challenge a medium-high risk transaction."""
        challenge_id = str(uuid.uuid4())

        return {
            "prevented": False,
            "actions_taken": [
                MitigationAction.CHALLENGE.value,
            ],
            "challenge_id": challenge_id,
            "escalation_required": False,
            "reason": "Transaction requires additional verification",
        }

    async def _escalate_for_review(
        self,
        assessment: TransactionAssessment,
    ) -> Dict[str, Any]:
        """Escalate transaction for human review."""
        escalation_id = str(uuid.uuid4())

        return {
            "prevented": False,
            "actions_taken": [
                MitigationAction.ESCALATE.value,
                MitigationAction.FLAG.value,
            ],
            "escalation_id": escalation_id,
            "escalation_required": True,
            "reason": "Transaction escalated for manual review",
        }

    async def record_fraud_attempt(
        self,
        entity_id: str,
        assessment: TransactionAssessment,
        prevented: bool = True,
    ) -> FraudAttempt:
        """Record a detected fraud attempt."""
        attempt = FraudAttempt(
            attempt_id=str(uuid.uuid4()),
            entity_id=entity_id,
            attempt_type=self._determine_attempt_type(assessment),
            risk_score=assessment.risk_score,
            confidence=assessment.confidence,
            indicators=assessment.indicators,
            affected_transactions=[assessment.transaction_id],
            detected_at=datetime.now(timezone.utc),
            prevented=prevented,
            prevention_method="automatic_blocking" if prevented else None,
            damage_estimated=self._estimate_damage(assessment),
        )

        return attempt

    def _determine_attempt_type(
        self,
        assessment: TransactionAssessment,
    ) -> str:
        """Determine the type of fraud attempt."""
        if assessment.risk_factors:
            return assessment.risk_factors[0].lower().replace(" ", "_")

        if "vpn" in str(assessment.indicators).lower():
            return "anonymous_transaction"
        elif "velocity" in str(assessment.indicators).lower():
            return "velocity_fraud"

        return "unknown_fraud"

    def _estimate_damage(self, assessment: TransactionAssessment) -> Optional[float]:
        """Estimate potential financial damage."""
        # Simple estimation based on risk score
        base_amount = assessment.amount_score * 10000
        damage = base_amount * assessment.risk_score
        return damage if damage > 100 else None

    async def check_account_protection(
        self,
        entity_id: str,
        recent_attempts: List[FraudAttempt],
    ) -> Dict[str, Any]:
        """Check if account needs protection."""
        if not recent_attempts:
            return {"needs_protection": False, "protection_level": "normal"}

        # Count recent attempts
        recent_count = len(recent_attempts)
        high_risk_count = sum(1 for a in recent_attempts if a.risk_score > 0.8)

        # Determine protection level
        if recent_count >= 5 or high_risk_count >= 3:
            return {
                "needs_protection": True,
                "protection_level": "maximum",
                "actions": [
                    "Freeze account",
                    "Require identity verification",
                    "Notify security team",
                ],
            }
        elif recent_count >= 2 or high_risk_count >= 1:
            return {
                "needs_protection": True,
                "protection_level": "elevated",
                "actions": [
                    "Enable additional monitoring",
                    "Limit transaction amounts",
                    "Require step-up authentication",
                ],
            }
        else:
            return {
                "needs_protection": False,
                "protection_level": "normal",
            }

    async def get_prevention_stats(self) -> Dict[str, Any]:
        """Get fraud prevention statistics."""
        return {
            "prevention_enabled": True,
            "auto_block_threshold": self._prevention_rules["auto_block_threshold"],
            "rules_active": len(self._prevention_rules),
        }


# Global engine instance
_engine: Optional[FraudPreventionEngine] = None


def get_prevention_engine() -> FraudPreventionEngine:
    """Get the fraud prevention engine instance."""
    global _engine
    if _engine is None:
        _engine = FraudPreventionEngine()
    return _engine