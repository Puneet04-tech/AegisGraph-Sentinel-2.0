import pytest

from src.mlops.model_metrics import (
    accuracy,
    classification_report,
    confusion_matrix,
    f1,
    mcc,
    precision,
    recall,
    specificity,
    thresholds_sweep,
)


def test_confusion_matrix_perfect():
    cm = confusion_matrix([1, 0, 1, 0, 1], [1, 0, 1, 0, 1])
    assert cm == {"tp": 3, "fp": 0, "tn": 2, "fn": 0}


def test_confusion_matrix_all_wrong():
    cm = confusion_matrix([1, 1, 0, 0], [0, 0, 1, 1])
    assert cm == {"tp": 0, "fp": 2, "tn": 0, "fn": 2}


def test_confusion_matrix_mixed():
    cm = confusion_matrix([1, 1, 0, 1, 0, 0, 1], [1, 0, 0, 1, 1, 0, 1])
    assert cm == {"tp": 3, "fp": 1, "tn": 2, "fn": 1}


def test_accuracy_empty_is_zero():
    assert accuracy([], []) == 0.0


def test_accuracy_perfect():
    assert accuracy([1, 1, 0, 0], [1, 1, 0, 0]) == 1.0


def test_accuracy_mixed():
    assert accuracy([1, 1, 0, 0], [1, 0, 0, 1]) == 0.5


def test_precision_recall_f1_known_values():
    labels = [1, 1, 1, 0, 0, 0, 1, 1]
    predictions = [1, 1, 0, 0, 1, 0, 1, 1]
    assert precision(labels, predictions) == pytest.approx(4 / 5)
    assert recall(labels, predictions) == pytest.approx(4 / 5)
    assert f1(labels, predictions) == pytest.approx(0.8)


def test_precision_zero_denominator_guard():
    assert precision([1, 1], [0, 0]) == 0.0


def test_recall_zero_denominator_guard():
    assert recall([0, 0], [1, 1]) == 0.0


def test_f1_zero_denominator_guard():
    assert f1([1, 1], [0, 0]) == 0.0


def test_specificity_known_value():
    labels = [1, 0, 0, 0, 1, 0]
    predictions = [1, 1, 0, 0, 1, 1]
    assert specificity(labels, predictions) == pytest.approx(2 / 4)


def test_mcc_perfect_is_one():
    assert mcc([1, 0, 1, 0], [1, 0, 1, 0]) == 1.0


def test_mcc_inverted_is_minus_one():
    assert mcc([1, 0, 1, 0], [0, 1, 0, 1]) == -1.0


def test_mcc_random_approx_zero():
    assert mcc([0, 0, 0, 1, 1, 1, 0, 1, 0, 1], [0, 1, 0, 0, 1, 0, 1, 0, 1, 1]) == pytest.approx(
        0.0, abs=0.25
    )


def test_mcc_zero_denominator_guard():
    assert mcc([1, 1, 1], [0, 0, 0]) == 0.0


def test_classification_report_contains_all_keys():
    labels = [1, 1, 0, 0, 1]
    predictions = [1, 0, 0, 1, 1]
    report = classification_report(labels, predictions)
    expected_keys = {
        "confusion_matrix",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "specificity",
        "mcc",
        "counts",
    }
    assert expected_keys <= set(report)
    assert report["confusion_matrix"] == {"tp": 2, "fp": 1, "tn": 1, "fn": 1}
    assert report["accuracy"] == pytest.approx(3 / 5)
    assert report["precision"] == pytest.approx(2 / 3)
    assert report["recall"] == pytest.approx(2 / 3)
    assert report["f1"] == pytest.approx(2 / 3)
    assert report["specificity"] == pytest.approx(1 / 2)
    assert report["counts"] == {"total": 5, "positive": 3, "negative": 2}


def test_thresholds_sweep_perfect_separation_has_f1_one():
    scores = [0.9, 0.8, 0.7, 0.1, 0.2, 0.3]
    labels = [1, 1, 1, 0, 0, 0]
    sweep = thresholds_sweep(scores, labels)
    assert any(row["f1"] == 1.0 for row in sweep)


def test_thresholds_sweep_length_and_order():
    scores = [0.9, 0.5, 0.9, 0.2, 0.5]
    labels = [1, 0, 1, 0, 0]
    sweep = thresholds_sweep(scores, labels)
    assert len(sweep) == 3
    thresholds = [row["threshold"] for row in sweep]
    assert thresholds == sorted(thresholds, reverse=True)


def test_thresholds_sweep_row_fields():
    scores = [0.8, 0.6, 0.4]
    labels = [1, 0, 1]
    row = thresholds_sweep(scores, labels)[1]
    assert set(row) == {"threshold", "tp", "fp", "tn", "fn", "f1", "precision", "recall"}


def test_length_mismatch_raises_value_error():
    with pytest.raises(ValueError):
        confusion_matrix([1, 0], [1])


def test_length_mismatch_raises_for_sweep():
    with pytest.raises(ValueError):
        thresholds_sweep([0.5, 0.6], [1, 0, 1])
