"""Classification metrics for binary fraud detection, with no external dependencies."""


def _require_matching_lengths(labels, predictions):
    if len(labels) != len(predictions):
        raise ValueError(
            f"labels and predictions length mismatch: {len(labels)} != {len(predictions)}"
        )


def confusion_matrix(labels, predictions):
    _require_matching_lengths(labels, predictions)
    tp = fp = tn = fn = 0
    for label, prediction in zip(labels, predictions):
        if prediction == 1:
            if label == 1:
                tp += 1
            else:
                fp += 1
        elif label == 1:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def accuracy(labels, predictions):
    _require_matching_lengths(labels, predictions)
    if not labels:
        return 0.0
    return sum(1 for label, prediction in zip(labels, predictions) if label == prediction) / len(
        labels
    )


def _safe_divide(numerator, denominator):
    return numerator / denominator if denominator else 0.0


def precision(labels, predictions):
    cm = confusion_matrix(labels, predictions)
    return _safe_divide(cm["tp"], cm["tp"] + cm["fp"])


def recall(labels, predictions):
    cm = confusion_matrix(labels, predictions)
    return _safe_divide(cm["tp"], cm["tp"] + cm["fn"])


def f1(labels, predictions):
    prec = precision(labels, predictions)
    rec = recall(labels, predictions)
    return _safe_divide(2 * prec * rec, prec + rec)


def specificity(labels, predictions):
    cm = confusion_matrix(labels, predictions)
    return _safe_divide(cm["tn"], cm["tn"] + cm["fp"])


def mcc(labels, predictions):
    cm = confusion_matrix(labels, predictions)
    numerator = cm["tp"] * cm["tn"] - cm["fp"] * cm["fn"]
    denominator = (
        (cm["tp"] + cm["fp"])
        * (cm["tp"] + cm["fn"])
        * (cm["tn"] + cm["fp"])
        * (cm["tn"] + cm["fn"])
    ) ** 0.5
    return _safe_divide(numerator, denominator)


def classification_report(labels, predictions):
    cm = confusion_matrix(labels, predictions)
    return {
        "confusion_matrix": cm,
        "accuracy": accuracy(labels, predictions),
        "precision": precision(labels, predictions),
        "recall": recall(labels, predictions),
        "f1": f1(labels, predictions),
        "specificity": specificity(labels, predictions),
        "mcc": mcc(labels, predictions),
        "counts": {"total": len(labels), "positive": cm["tp"] + cm["fn"], "negative": cm["tn"] + cm["fp"]},
    }


def thresholds_sweep(scores, labels):
    _require_matching_lengths(scores, labels)
    thresholds = sorted(set(scores), reverse=True)
    results = []
    for threshold in thresholds:
        predictions = [1 if score >= threshold else 0 for score in scores]
        cm = confusion_matrix(labels, predictions)
        prec = precision(labels, predictions)
        rec = recall(labels, predictions)
        results.append(
            {
                "threshold": threshold,
                "tp": cm["tp"],
                "fp": cm["fp"],
                "tn": cm["tn"],
                "fn": cm["fn"],
                "f1": f1(labels, predictions),
                "precision": prec,
                "recall": rec,
            }
        )
    return results
