"""Threshold optimization utilities for fraud classification.

Given model scores (higher means more risky) and ground-truth labels,
these helpers compute confusion-matrix metrics at a score cutoff, trace
the ROC curve, and locate the cutoff that optimizes a chosen metric.
"""

from typing import Dict, List


def evaluate_threshold(scores: List[float], labels: List[int], threshold: float) -> Dict[str, float]:
    """Compute confusion-matrix metrics classifying score >= threshold as positive."""
    tp = fp = tn = fn = 0
    for score, label in zip(scores, labels):
        if score >= threshold:
            if label == 1:
                tp += 1
            else:
                fp += 1
        elif label == 1:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positive_rate": recall,
        "false_positive_rate": false_positive_rate,
        "accuracy": accuracy,
    }


def roc_points(scores: List[float], labels: List[int], num_steps: int = 100) -> List[Dict[str, float]]:
    """Return (fpr, tpr) points for thresholds swept from max to min score."""
    if not scores:
        return []
    high, low = max(scores), min(scores)
    step = (high - low) / (num_steps - 1) if num_steps > 1 else 0.0
    points = []
    for i in range(num_steps):
        threshold = high - step * i
        metrics = evaluate_threshold(scores, labels, threshold)
        points.append({
            "threshold": threshold,
            "fpr": metrics["false_positive_rate"],
            "tpr": metrics["true_positive_rate"],
        })
    return points


_METRIC_KEYS = {
    "f1": "f1",
    "precision": "precision",
    "recall": "recall",
    "accuracy": "accuracy",
}


def choose_metric(name: str) -> str:
    """Map a user-facing metric name to its evaluate_threshold key."""
    if name not in _METRIC_KEYS:
        raise ValueError(f"unknown metric: {name}")
    return _METRIC_KEYS[name]


def best_threshold(scores: List[float], labels: List[int], metric: str = "f1", *, minimize: bool = False) -> Dict[str, float]:
    """Return metrics for the cutoff that optimizes the requested metric."""
    key = choose_metric(metric)
    unique = sorted(set(scores))
    if unique:
        candidates = [unique[-1] + 1.0] + unique + [unique[0] - 1.0]
    else:
        candidates = [0.0]
    results = []
    for threshold in candidates:
        metrics = evaluate_threshold(scores, labels, threshold)
        results.append({**metrics, "threshold": threshold, "value": metrics[key]})
    results.sort(key=lambda r: r["threshold"])
    results.sort(key=lambda r: r["value"], reverse=not minimize)
    return results[0]
