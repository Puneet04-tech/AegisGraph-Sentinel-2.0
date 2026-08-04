"""Unit tests for the adaptive learning engine.

Covers ``src.adaptive_risk_control.adaptive_learning.AdaptiveLearningEngine``:
feedback processing, periodic model updates, accuracy calculation,
assessment-outcome learning, statistics, and reset behaviour.
"""

from __future__ import annotations

import asyncio
from typing import Dict

import pytest

from src.adaptive_risk_control.adaptive_learning import (
    AdaptiveLearningEngine,
    get_learning_engine,
)
from src.adaptive_risk_control.models import (
    DecisionType,
    LearningFeedback,
    LearningFeedbackType,
    RiskLevel,
    TransactionAssessment,
)


def _feedback(
    predicted: float = 0.5,
    actual: float = 0.5,
    feedback_type: LearningFeedbackType = LearningFeedbackType.POSITIVE,
) -> LearningFeedback:
    return LearningFeedback(
        feedback_id="fb-1",
        entity_id="entity-1",
        transaction_id="txn-1",
        feedback_type=feedback_type,
        risk_score_predicted=predicted,
        risk_score_actual=actual,
        features={"velocity_score": 0.5},
        model_version="1.0.0",
    )


def _assessment(risk_score: float = 0.5) -> TransactionAssessment:
    return TransactionAssessment(
        assessment_id="a-1",
        transaction_id="txn-1",
        entity_id="entity-1",
        risk_score=risk_score,
        risk_level=RiskLevel.MEDIUM,
        decision=DecisionType.MONITOR,
        confidence=0.8,
        risk_factors=["velocity"],
        indicators=["VELOCITY_SPIKE"],
        velocity_score=0.6,
        behavioral_score=0.4,
        device_score=0.3,
        location_score=0.2,
        amount_score=0.5,
    )


@pytest.fixture
def engine() -> AdaptiveLearningEngine:
    return AdaptiveLearningEngine()


# ---------------------------------------------------------------------------
# Statistics initialization and updates
# ---------------------------------------------------------------------------


class TestStats:
    def test_initialize_stats_zeroed(self, engine):
        stats = engine._initialize_stats()

        assert stats["total_feedback"] == 0
        assert stats["positive_feedback"] == 0
        assert stats["negative_feedback"] == 0
        assert stats["false_positives"] == 0
        assert stats["false_negatives"] == 0
        assert stats["model_updates"] == 0

    def test_update_stats_increments_each_type(self, engine):
        engine._update_stats(_feedback(feedback_type=LearningFeedbackType.POSITIVE))
        engine._update_stats(_feedback(feedback_type=LearningFeedbackType.NEGATIVE))
        engine._update_stats(_feedback(feedback_type=LearningFeedbackType.FALSE_POSITIVE))
        engine._update_stats(_feedback(feedback_type=LearningFeedbackType.FALSE_NEGATIVE))

        stats = engine._learning_stats
        assert stats["total_feedback"] == 4
        assert stats["positive_feedback"] == 1
        assert stats["negative_feedback"] == 1
        assert stats["false_positives"] == 1
        assert stats["false_negatives"] == 1


# ---------------------------------------------------------------------------
# Feedback processing
# ---------------------------------------------------------------------------


class TestFeedbackProcessing:
    def test_process_feedback_buffers_and_returns_result(self, engine):
        result = asyncio.run(engine.process_feedback(_feedback()))

        assert result["processed"] is True
        assert result["feedback_id"] == "fb-1"
        assert result["model_updated"] is False
        assert len(engine._feedback_buffer) == 1

    def test_should_update_model_threshold(self, engine):
        assert engine._should_update_model() is False
        for _ in range(100):
            engine._feedback_buffer.append(_feedback())
        assert engine._should_update_model() is True

    def test_model_update_bumps_version_and_clears_buffer(self, engine):
        for _ in range(100):
            asyncio.run(engine.process_feedback(_feedback()))

        assert engine._model_version == "1.0.1"
        assert len(engine._feedback_buffer) == 50
        assert engine._learning_stats["model_updates"] == 1

    def test_accuracy_calculation(self, engine):
        correct = _feedback(predicted=0.5, actual=0.55)
        correct2 = _feedback(predicted=0.8, actual=0.7)
        wrong = _feedback(predicted=0.2, actual=0.9)

        assert engine._calculate_accuracy([correct, correct2, wrong]) == pytest.approx(2 / 3)

    def test_accuracy_empty_list_is_zero(self, engine):
        assert engine._calculate_accuracy([]) == 0.0


# ---------------------------------------------------------------------------
# Feedback type determination
# ---------------------------------------------------------------------------


class TestFeedbackType:
    def test_positive_within_small_delta(self, engine):
        assert engine._determine_feedback_type(0.5, {"actual_risk_score": 0.55}) == (
            LearningFeedbackType.POSITIVE
        )

    def test_false_positive_when_predicted_much_higher(self, engine):
        assert engine._determine_feedback_type(0.9, {"actual_risk_score": 0.3}) == (
            LearningFeedbackType.FALSE_POSITIVE
        )

    def test_false_negative_when_predicted_much_lower(self, engine):
        assert engine._determine_feedback_type(0.2, {"actual_risk_score": 0.8}) == (
            LearningFeedbackType.FALSE_NEGATIVE
        )

    def test_adjustment_for_moderate_delta(self, engine):
        assert engine._determine_feedback_type(0.5, {"actual_risk_score": 0.65}) == (
            LearningFeedbackType.ADJUSTMENT
        )

    def test_default_actual_equals_predicted(self, engine):
        assert engine._determine_feedback_type(0.5, {}) == LearningFeedbackType.POSITIVE


# ---------------------------------------------------------------------------
# Assessment learning
# ---------------------------------------------------------------------------


class TestAssessmentLearning:
    def test_learn_from_assessment_builds_feedback(self, engine):
        feedback = asyncio.run(
            engine.learn_from_assessment(_assessment(0.5), {"actual_risk_score": 0.55})
        )

        assert feedback.entity_id == "entity-1"
        assert feedback.transaction_id == "txn-1"
        assert feedback.feedback_type == LearningFeedbackType.POSITIVE
        assert feedback.risk_score_predicted == 0.5
        assert feedback.risk_score_actual == 0.55
        assert feedback.features["velocity_score"] == 0.6
        assert feedback.features["behavioral_score"] == 0.4
        assert feedback.features["device_score"] == 0.3
        assert feedback.features["location_score"] == 0.2
        assert feedback.features["amount_score"] == 0.5

    def test_learn_from_assessment_is_processed(self, engine):
        asyncio.run(
            engine.learn_from_assessment(_assessment(0.5), {"actual_risk_score": 0.9})
        )

        assert engine._learning_stats["total_feedback"] == 1
        assert engine._learning_stats["false_negatives"] == 1


# ---------------------------------------------------------------------------
# Statistics and reset
# ---------------------------------------------------------------------------


class TestStatsAndReset:
    def test_get_learning_stats_without_feedback(self, engine):
        stats = asyncio.run(engine.get_learning_stats())

        assert stats["accuracy"] == 0
        assert stats["false_positive_rate"] == 0
        assert stats["false_negative_rate"] == 0
        assert stats["model_version"] == "1.0.0"
        assert stats["buffer_size"] == 0

    def test_get_learning_stats_with_feedback(self, engine):
        asyncio.run(engine.process_feedback(_feedback(predicted=0.5, actual=0.55)))

        stats = asyncio.run(engine.get_learning_stats())
        assert stats["total_feedback"] == 1
        assert stats["accuracy"] == 1.0
        assert stats["false_positive_rate"] == 0.0
        assert stats["false_negative_rate"] == 0.0

    def test_reset_learning_clears_state(self, engine):
        for _ in range(100):
            asyncio.run(engine.process_feedback(_feedback()))
        engine._model_version = "2.0.5"

        result = asyncio.run(engine.reset_learning())

        assert result["status"] == "reset"
        assert result["buffer_cleared"] is True
        assert engine._model_version == "1.0.0"
        assert engine._feedback_buffer == []
        assert engine._learning_stats["total_feedback"] == 0

    def test_get_model_parameters(self, engine):
        params = asyncio.run(engine.get_model_parameters())

        assert params["model_version"] == "1.0.0"
        assert params["risk_factor_weights"]["velocity"] == 0.25
        assert params["decision_thresholds"]["block"] == 0.9
        assert params["learning_rate"] == 0.1
        assert params["update_frequency"] == 100


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_learning_engine_singleton(self):
        first = get_learning_engine()
        second = get_learning_engine()

        assert first is second
        assert isinstance(first, AdaptiveLearningEngine)
