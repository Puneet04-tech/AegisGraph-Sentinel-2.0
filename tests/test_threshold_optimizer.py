"""Tests for the threshold optimizer module."""

import pytest

from src.analytics_business_intelligence.threshold_optimizer import (
    best_threshold,
    choose_metric,
    evaluate_threshold,
    roc_points,
)

SEPARABLE_SCORES = [0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9]
SEPARABLE_LABELS = [0, 0, 0, 0, 1, 1, 1, 1]

ROC_SCORES = [
    0.95, 0.90, 0.88, 0.86, 0.84, 0.80, 0.60, 0.55, 0.45, 0.35,
    0.85, 0.70, 0.50, 0.40, 0.30, 0.20,
]
ROC_LABELS = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]


def test_evaluate_threshold_counts():
    scores = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0]
    labels = [1, 1, 1, 0, 0, 1, 0, 0, 1, 0]
    metrics = evaluate_threshold(scores, labels, 0.5)
    assert metrics["tp"] == 3
    assert metrics["fp"] == 2
    assert metrics["tn"] == 3
    assert metrics["fn"] == 2


def test_evaluate_threshold_rates():
    scores = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0]
    labels = [1, 1, 1, 0, 0, 1, 0, 0, 1, 0]
    metrics = evaluate_threshold(scores, labels, 0.5)
    assert metrics["precision"] == pytest.approx(0.6)
    assert metrics["recall"] == pytest.approx(0.6)
    assert metrics["f1"] == pytest.approx(0.6)
    assert metrics["true_positive_rate"] == pytest.approx(0.6)
    assert metrics["false_positive_rate"] == pytest.approx(0.4)
    assert metrics["accuracy"] == pytest.approx(0.6)


def test_evaluate_threshold_guards_divide_by_zero():
    metrics = evaluate_threshold([0.9, 0.7, 0.5], [0, 0, 0], 0.5)
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1"] == 0.0
    assert metrics["true_positive_rate"] == 0.0
    assert metrics["false_positive_rate"] == 1.0
    assert metrics["accuracy"] == 0.0


def test_evaluate_threshold_empty():
    metrics = evaluate_threshold([], [], 0.5)
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1"] == 0.0
    assert metrics["accuracy"] == 0.0


def test_roc_points_extremes():
    points = roc_points(ROC_SCORES, ROC_LABELS, num_steps=100)
    assert len(points) == 100
    assert points[0]["threshold"] == pytest.approx(max(ROC_SCORES))
    assert points[0]["fpr"] == 0.0
    assert points[0]["tpr"] == pytest.approx(0.1)
    assert points[-1]["threshold"] == pytest.approx(min(ROC_SCORES))
    assert points[-1]["tpr"] == 1.0
    assert points[-1]["fpr"] == 1.0


def test_roc_points_bounds():
    points = roc_points(ROC_SCORES, ROC_LABELS)
    assert all(0.0 <= p["fpr"] <= 1.0 for p in points)
    assert all(0.0 <= p["tpr"] <= 1.0 for p in points)
    assert all(points[i]["threshold"] >= points[i + 1]["threshold"] for i in range(len(points) - 1))


def test_best_threshold_separable_f1():
    result = best_threshold(SEPARABLE_SCORES, SEPARABLE_LABELS)
    assert result["value"] == 1.0
    assert result["f1"] == 1.0
    assert result["tp"] == 4
    assert result["fp"] == 0


def test_best_threshold_tie_breaks_to_lowest():
    result = best_threshold(SEPARABLE_SCORES, SEPARABLE_LABELS)
    assert result["value"] == 1.0
    assert result["threshold"] == pytest.approx(0.6)


def test_best_threshold_precision():
    result = best_threshold(SEPARABLE_SCORES, SEPARABLE_LABELS, metric="precision")
    assert result["value"] == 1.0
    assert result["precision"] == 1.0
    assert result["threshold"] == pytest.approx(0.6)


def test_best_threshold_accuracy():
    result = best_threshold(SEPARABLE_SCORES, SEPARABLE_LABELS, metric="accuracy")
    assert result["value"] == 1.0
    assert result["accuracy"] == 1.0


def test_best_threshold_minimize():
    result = best_threshold(SEPARABLE_SCORES, SEPARABLE_LABELS, minimize=True)
    assert result["value"] == 0.0
    assert result["f1"] == 0.0
    assert result["threshold"] == pytest.approx(1.9)


def test_best_threshold_returns_all_metrics():
    result = best_threshold(SEPARABLE_SCORES, SEPARABLE_LABELS)
    expected = {
        "threshold", "value", "tp", "fp", "tn", "fn",
        "precision", "recall", "f1", "true_positive_rate",
        "false_positive_rate", "accuracy",
    }
    assert expected <= set(result)


def test_choose_metric_valid():
    assert choose_metric("f1") == "f1"
    assert choose_metric("precision") == "precision"
    assert choose_metric("recall") == "recall"
    assert choose_metric("accuracy") == "accuracy"


def test_choose_metric_unknown():
    with pytest.raises(ValueError):
        choose_metric("auc")
    with pytest.raises(ValueError):
        choose_metric("F1")


def test_best_threshold_unknown_metric():
    with pytest.raises(ValueError):
        best_threshold(SEPARABLE_SCORES, SEPARABLE_LABELS, metric="auc")
