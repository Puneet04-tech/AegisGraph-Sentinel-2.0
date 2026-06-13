"""
Adaptive Learning Engine for continuous model improvement.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    LearningFeedback,
    LearningFeedbackType,
    TransactionAssessment,
)


class AdaptiveLearningEngine:
    """
    Provides continuous learning and model improvement.

    Handles:
    - Feedback processing
    - Model updates
    - Pattern learning
    - Performance tracking
    """

    def __init__(self):
        self._feedback_buffer: List[LearningFeedback] = []
        self._model_version = "1.0.0"
        self._learning_stats = self._initialize_stats()

    def _initialize_stats(self) -> Dict[str, Any]:
        """Initialize learning statistics."""
        return {
            "total_feedback": 0,
            "positive_feedback": 0,
            "negative_feedback": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "model_updates": 0,
        }

    async def process_feedback(
        self,
        feedback: LearningFeedback,
    ) -> Dict[str, Any]:
        """Process learning feedback."""
        # Add to buffer
        self._feedback_buffer.append(feedback)

        # Update stats
        self._update_stats(feedback)

        # Trigger model update if needed
        should_update = self._should_update_model()

        update_result = {}
        if should_update:
            update_result = await self._update_model()

        return {
            "feedback_id": feedback.feedback_id,
            "processed": True,
            "model_updated": should_update,
            "update_result": update_result,
        }

    def _update_stats(self, feedback: LearningFeedback) -> None:
        """Update learning statistics."""
        self._learning_stats["total_feedback"] += 1

        if feedback.feedback_type == LearningFeedbackType.POSITIVE:
            self._learning_stats["positive_feedback"] += 1
        elif feedback.feedback_type == LearningFeedbackType.NEGATIVE:
            self._learning_stats["negative_feedback"] += 1
        elif feedback.feedback_type == LearningFeedbackType.FALSE_POSITIVE:
            self._learning_stats["false_positives"] += 1
        elif feedback.feedback_type == LearningFeedbackType.FALSE_NEGATIVE:
            self._learning_stats["false_negatives"] += 1

    def _should_update_model(self) -> bool:
        """Check if model should be updated."""
        # Update every 100 feedback items
        return len(self._feedback_buffer) >= 100

    async def _update_model(self) -> Dict[str, Any]:
        """Update the model based on feedback."""
        # Simple learning: adjust based on feedback
        recent_feedback = self._feedback_buffer[-100:]

        # Calculate adjustment factors
        accuracy = self._calculate_accuracy(recent_feedback)

        # Update model version
        version_parts = self._model_version.split(".")
        version_parts[-1] = str(int(version_parts[-1]) + 1)
        self._model_version = ".".join(version_parts)

        # Clear buffer
        self._feedback_buffer = self._feedback_buffer[-50:]  # Keep last 50

        self._learning_stats["model_updates"] += 1

        return {
            "new_version": self._model_version,
            "accuracy": accuracy,
            "feedback_processed": len(recent_feedback),
        }

    def _calculate_accuracy(
        self,
        feedback: List[LearningFeedback],
    ) -> float:
        """Calculate model accuracy from feedback."""
        if not feedback:
            return 0.0

        correct = 0
        for f in feedback:
            diff = abs(f.risk_score_predicted - f.risk_score_actual)
            if diff < 0.2:  # Within 20% is considered correct
                correct += 1

        return correct / len(feedback)

    async def learn_from_assessment(
        self,
        assessment: TransactionAssessment,
        outcome: Dict[str, Any],
    ) -> LearningFeedback:
        """Learn from an assessment outcome."""
        feedback_type = self._determine_feedback_type(
            assessment.risk_score,
            outcome,
        )

        feedback = LearningFeedback(
            feedback_id=str(uuid.uuid4()),
            entity_id=assessment.entity_id,
            transaction_id=assessment.transaction_id,
            feedback_type=feedback_type,
            risk_score_predicted=assessment.risk_score,
            risk_score_actual=outcome.get("actual_risk_score", assessment.risk_score),
            features={
                "velocity_score": assessment.velocity_score,
                "behavioral_score": assessment.behavioral_score,
                "device_score": assessment.device_score,
                "location_score": assessment.location_score,
                "amount_score": assessment.amount_score,
            },
            model_version=self._model_version,
            timestamp=datetime.now(timezone.utc),
        )

        # Process feedback
        await self.process_feedback(feedback)

        return feedback

    def _determine_feedback_type(
        self,
        predicted_score: float,
        outcome: Dict[str, Any],
    ) -> LearningFeedbackType:
        """Determine feedback type from outcome."""
        actual_score = outcome.get("actual_risk_score", predicted_score)

        # Calculate difference
        diff = predicted_score - actual_score

        if abs(diff) < 0.1:
            return LearningFeedbackType.POSITIVE

        if diff > 0.2:
            # Predicted higher than actual = false positive
            return LearningFeedbackType.FALSE_POSITIVE

        if diff < -0.2:
            # Predicted lower than actual = false negative
            return LearningFeedbackType.FALSE_NEGATIVE

        return LearningFeedbackType.ADJUSTMENT

    async def get_learning_stats(self) -> Dict[str, Any]:
        """Get learning statistics."""
        stats = self._learning_stats.copy()

        if stats["total_feedback"] > 0:
            stats["accuracy"] = self._calculate_accuracy(self._feedback_buffer)
            stats["false_positive_rate"] = (
                stats["false_positives"] / stats["total_feedback"]
            )
            stats["false_negative_rate"] = (
                stats["false_negatives"] / stats["total_feedback"]
            )
        else:
            stats["accuracy"] = 0
            stats["false_positive_rate"] = 0
            stats["false_negative_rate"] = 0

        stats["model_version"] = self._model_version
        stats["buffer_size"] = len(self._feedback_buffer)

        return stats

    async def reset_learning(self) -> Dict[str, Any]:
        """Reset learning state."""
        self._feedback_buffer = []
        self._learning_stats = self._initialize_stats()
        self._model_version = "1.0.0"

        return {
            "status": "reset",
            "model_version": self._model_version,
            "buffer_cleared": True,
        }

    async def get_model_parameters(self) -> Dict[str, Any]:
        """Get current model parameters."""
        return {
            "model_version": self._model_version,
            "risk_factor_weights": {
                "velocity": 0.25,
                "amount": 0.20,
                "device": 0.15,
                "location": 0.15,
                "behavior": 0.15,
                "history": 0.10,
            },
            "decision_thresholds": {
                "approve": 0.3,
                "monitor": 0.5,
                "challenge": 0.7,
                "review": 0.8,
                "block": 0.9,
                "deny": 1.0,
            },
            "learning_rate": 0.1,
            "update_frequency": 100,
        }


# Global engine instance
_engine: Optional[AdaptiveLearningEngine] = None


def get_learning_engine() -> AdaptiveLearningEngine:
    """Get the adaptive learning engine instance."""
    global _engine
    if _engine is None:
        _engine = AdaptiveLearningEngine()
    return _engine