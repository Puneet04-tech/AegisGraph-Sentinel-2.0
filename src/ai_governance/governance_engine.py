"""
AI Governance Engine
Security, drift detection, bias detection, and explainability.
"""
import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
import random

import numpy as np
from scipy import stats as scipy_stats

from .models import (
    Model,
    ModelDrift,
    DriftType,
    BiasReport,
    BiasMetric,
    ModelExplanation,
    AuditRecord,
)
from .registry import ModelRegistry, get_model_registry


# ---------------------------------------------------------------------------
# Drift detection helpers (Population Stability Index)
# ---------------------------------------------------------------------------
#
# PSI bins with zero mass on either side are floored to this value before
# the log-ratio is taken, so a single empty bin cannot produce log(0) or a
# division by zero.
_PSI_EPSILON = 1e-4
# Deciles: the conventional bin count for PSI in credit-risk model
# monitoring -- fine-grained enough to be sensitive without over-fitting to
# small baseline samples.
_PSI_BIN_COUNT = 10
# Below this fraction of features actually being scorable, an aggregate
# drift score is built from less than half the tracked schema and is no
# longer a representative monitoring signal, even though a (partial)
# number can still be computed. Flagged for review rather than trusted
# silently.
_MIN_FEATURE_COVERAGE = 0.5


def _is_number(value: Any) -> bool:
    """True for a real (non-NaN, non-bool) int/float."""
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return not (isinstance(value, float) and math.isnan(value))
    return False


def _is_missing(value: Any) -> bool:
    """True for a value that carries no information: ``None``, or a float
    ``NaN``. Used consistently wherever a feature's "is it present at all"
    question is asked, so a NaN is never accidentally treated as a
    legitimate category (see `_categorical_psi`) or as the reason a
    feature that is otherwise entirely numeric gets misclassified as
    categorical (see `_analyze_drift`)."""
    return value is None or (isinstance(value, float) and math.isnan(value))


def _numeric_psi(
    baseline_values: List[Any],
    current_values: List[Any],
) -> Tuple[Optional[float], Optional[str]]:
    """Population Stability Index for one numeric feature.

        PSI = sum_i (cur_pct_i - base_pct_i) * ln(cur_pct_i / base_pct_i)

    Bin edges are fixed quantile cut points (deciles) computed from
    ``baseline_values`` only, so the same baseline always produces the same
    bins -- re-running with identical inputs is reproducible, and
    ``current_values`` is scored against a stationary reference rather than
    one that moves with it. ``None``/``NaN``/non-numeric entries are
    dropped before binning.

    Returns ``(psi, None)`` on success, or ``(None, reason)`` if the value
    is not computable: either side has zero valid numeric observations, or
    the baseline is degenerate (fewer than two distinct values, including
    the common single-record-baseline case) -- with only one distinct
    baseline value there is no distribution to compare against, so PSI is
    undefined rather than a number obtained by inventing a bin boundary.
    This mirrors the same convention used by
    ``src.mlops.drift_monitor.population_stability_index`` elsewhere in
    this codebase.
    """
    baseline_arr = np.array([v for v in baseline_values if _is_number(v)], dtype=float)
    current_arr = np.array([v for v in current_values if _is_number(v)], dtype=float)

    if baseline_arr.size == 0:
        return None, "baseline has no valid numeric observations"
    if current_arr.size == 0:
        return None, "current has no valid numeric observations"

    quantiles = np.linspace(0.0, 1.0, _PSI_BIN_COUNT + 1)
    edges = np.unique(np.quantile(baseline_arr, quantiles))

    if edges.size < 2:
        return None, "baseline is degenerate (fewer than 2 distinct values); PSI is undefined"

    edges[0] = -np.inf
    edges[-1] = np.inf

    baseline_counts, _ = np.histogram(baseline_arr, bins=edges)
    current_counts, _ = np.histogram(current_arr, bins=edges)

    baseline_pct = baseline_counts / baseline_arr.size
    current_pct = current_counts / current_arr.size
    baseline_pct = np.where(baseline_pct == 0, _PSI_EPSILON, baseline_pct)
    current_pct = np.where(current_pct == 0, _PSI_EPSILON, current_pct)

    psi = float(np.sum((current_pct - baseline_pct) * np.log(current_pct / baseline_pct)))
    return psi, None


def _categorical_psi(
    baseline_values: List[Any],
    current_values: List[Any],
) -> Tuple[Optional[float], Optional[str]]:
    """Population Stability Index for one categorical feature.

    Same formula as `_numeric_psi`, computed over category frequencies
    instead of quantile bins. The category set is the union of baseline and
    current categories, so a category seen in only one of the two samples
    ("unseen" on the other side) still contributes a term -- via epsilon
    smoothing on the side where its frequency is zero -- instead of being
    dropped. ``None``/``NaN`` entries are treated as missing and excluded
    (a `NaN` is never a legitimate category, so it must not be scored as an
    "unseen" one -- see `_is_missing`).

    Returns ``(psi, None)`` on success, or ``(None, reason)`` if either
    side has zero valid observations.
    """
    baseline_vals = [v for v in baseline_values if not _is_missing(v)]
    current_vals = [v for v in current_values if not _is_missing(v)]

    if not baseline_vals:
        return None, "baseline has no non-null observations"
    if not current_vals:
        return None, "current has no non-null observations"

    baseline_counts = Counter(baseline_vals)
    current_counts = Counter(current_vals)
    categories = set(baseline_counts) | set(current_counts)
    baseline_total = len(baseline_vals)
    current_total = len(current_vals)

    psi = 0.0
    for category in categories:
        baseline_pct = baseline_counts.get(category, 0) / baseline_total or _PSI_EPSILON
        current_pct = current_counts.get(category, 0) / current_total or _PSI_EPSILON
        psi += (current_pct - baseline_pct) * math.log(current_pct / baseline_pct)

    return float(psi), None


def _psi_to_drift_score(psi: float) -> float:
    """Map a PSI value onto this engine's ``[0, 1]`` drift-score scale,
    where -- per the direction convention used throughout this module --
    higher means *more* drifted.

    Uses the standard PSI interpretation bands from credit-risk model
    monitoring::

        PSI < 0.10              stable       (no significant drift)
        0.10 <= PSI < 0.25       moderate     (investigate)
        PSI >= 0.25              significant  (retrain / alert)

    The bands are mapped piecewise-linearly onto ``[0, 1]`` so the
    stable/moderate boundary (PSI 0.10) lands at 0.40 and the
    moderate/significant boundary (PSI 0.25) lands at 0.70 -- aligning with
    `DriftDetectionEngine.detect_drift`'s existing severity buckets
    (MEDIUM > 0.4, HIGH > 0.6, CRITICAL > 0.8). PSI beyond 0.25 keeps
    raising the score, saturating at 1.0 once PSI reaches 0.5 (a
    near-total distribution shift), which lands squarely in CRITICAL.
    """
    psi = max(0.0, psi)
    if psi < 0.10:
        return (psi / 0.10) * 0.40
    if psi < 0.25:
        return 0.40 + ((psi - 0.10) / 0.15) * 0.30
    return min(1.0, 0.70 + ((psi - 0.25) / 0.25) * 0.30)


# ---------------------------------------------------------------------------
# Bias detection helpers
# ---------------------------------------------------------------------------

_BIAS_THRESHOLD = 0.8
# A metric needs at least two protected groups with usable data to say
# anything about disparity between them.
_MIN_GROUPS_REQUIRED = 2
# EQUALIZED_ODDS / CALIBRATION need ground-truth labels, which the request
# schema only carries as an optional per-record "label" key -- a caller may
# label only a subset of `predictions`. Below this many labeled records
# total, any computed rate is statistical noise rather than a signal.
_MIN_LABELED_TOTAL = 5
# A group with only 1 labeled record has a rate that is either exactly 0%
# or exactly 100% no matter what the group's true rate is -- that single
# coin-flip would make a genuinely fair model look arbitrarily biased (or
# a biased one look fair) purely from sample-size noise. Below this count,
# the *entire* metric is reported not_computable rather than silently
# excluding the undersized group and computing a disparity across the
# survivors, which would understate the real disparity.
_MIN_LABELED_PER_GROUP = 2


def _to_binary(value: Any) -> Optional[bool]:
    """Interpret a raw prediction/label value as a positive (``True``) or
    negative (``False``) binary outcome.

    - ``bool`` -> the value itself.
    - ``int``/``float`` -> ``True`` if ``>= 0.5`` (treats a continuous
      score/probability using the conventional 0.5 decision threshold);
      ``NaN`` is treated as missing.
    - ``str`` -> case-insensitive match against a small affirmative/
      negative vocabulary; anything else is unparseable.
    - ``None`` -> missing.

    Returns ``None`` for missing/unparseable input rather than guessing.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and math.isnan(value):
            return None
        return value >= 0.5
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("1", "true", "yes", "positive", "favorable"):
            return True
        if token in ("0", "false", "no", "negative", "unfavorable"):
            return False
    return None


def _to_score(value: Any) -> Optional[float]:
    """Parse a raw value as a continuous numeric score (e.g. a predicted
    probability). Returns ``None`` for missing/``NaN``/non-numeric input."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if isinstance(value, float) and math.isnan(value):
            return None
        return float(value)
    return None


def _group_binary_values(
    records: List[Dict[str, Any]],
    group_key: str,
    value_key: str,
) -> Dict[Any, List[bool]]:
    """Bucket a binary field's values by protected-attribute group.

    Records missing ``group_key``, missing ``value_key``, or with an
    unparseable value for either are excluded rather than silently
    coerced into a group or an outcome.
    """
    groups: Dict[Any, List[bool]] = {}
    for record in records:
        if group_key not in record or record[group_key] is None:
            continue
        value = _to_binary(record.get(value_key))
        if value is None:
            continue
        groups.setdefault(record[group_key], []).append(value)
    return groups


def _group_positive_rates(groups: Dict[Any, List[bool]]) -> Dict[Any, float]:
    """Positive-outcome rate per group; groups with zero valid members are
    already absent from ``groups`` and stay absent here."""
    return {group: sum(values) / len(values) for group, values in groups.items() if values}


def _demographic_parity_score(
    rates: Dict[Any, float],
) -> Tuple[Optional[float], List[Any], Dict[str, Any]]:
    """``1 - max pairwise difference`` in positive-prediction rate across
    groups.

    Demographic parity requires ``P(pred=1 | group=g)`` to be equal across
    every group ``g``; the disparity is the widest gap between any two
    groups' positive rates. Returning ``1 - disparity`` keeps the result on
    this engine's "higher = fairer" score scale (see ``get_compliance_status``
    and the ``is_fair = score >= threshold`` convention).

    Not computable with fewer than two groups.
    """
    if len(rates) < _MIN_GROUPS_REQUIRED:
        return None, [], {
            "reason": "fewer than 2 protected groups had usable prediction data",
            "groups_considered": sorted(map(str, rates)),
        }
    disparity = max(rates.values()) - min(rates.values())
    disadvantaged = min(rates, key=rates.get)
    details = {
        "groups_considered": sorted(map(str, rates)),
        "group_rates": {str(g): round(r, 6) for g, r in rates.items()},
    }
    return max(0.0, 1.0 - disparity), [disadvantaged], details


def _disparate_impact_score(
    rates: Dict[Any, float],
) -> Tuple[Optional[float], List[Any], Dict[str, Any]]:
    """Disparate impact ratio: ``min(group rate) / max(group rate)`` -- the
    EEOC "80% rule". A ratio of 1.0 is perfect parity; a ratio below 0.8 is
    the conventional threshold for adverse impact, which lines up directly
    with this engine's fairness threshold.

    If the maximum rate is 0 (no group ever receives a positive
    prediction), every group is being treated identically, so the ratio is
    defined as 1.0 rather than raising a division error.

    Not computable with fewer than two groups.
    """
    if len(rates) < _MIN_GROUPS_REQUIRED:
        return None, [], {
            "reason": "fewer than 2 protected groups had usable prediction data",
            "groups_considered": sorted(map(str, rates)),
        }
    max_rate = max(rates.values())
    min_rate = min(rates.values())
    disadvantaged = min(rates, key=rates.get)
    details = {
        "groups_considered": sorted(map(str, rates)),
        "group_rates": {str(g): round(r, 6) for g, r in rates.items()},
    }
    if max_rate == 0:
        return 1.0, [], details
    return min_rate / max_rate, [disadvantaged], details


def _equalized_odds_score(
    records: List[Dict[str, Any]],
    group_key: str,
) -> Tuple[Optional[float], List[Any], Dict[str, Any]]:
    """``1 - max(pairwise TPR gap, pairwise FPR gap)`` across groups.

    Equalized odds requires both the true-positive rate
    ``P(pred=1 | y=1, group=g)`` and the false-positive rate
    ``P(pred=1 | y=0, group=g)`` to be equal across groups. This requires
    ground-truth labels: each prediction record may optionally carry a
    ``"label"`` key (the request schema otherwise only carries
    ``predictions`` + ``protected_attributes``, so labels are opt-in per
    record rather than a required top-level field).

    A caller may label only a subset of records ("partial labels"); this
    metric computes on that labeled subset alone and reports coverage via
    ``details["label_coverage"]``. Guard rails, in order:

    1. Fewer than `_MIN_LABELED_TOTAL` labeled records overall -> not
       computable (too little data to say anything).
    2. Fewer than 2 protected groups present in the labeled subset -> not
       computable (nothing to compare).
    3. Any present group with fewer than `_MIN_LABELED_PER_GROUP` labeled
       records -> not computable for the *whole* metric, naming the
       offending group(s). Silently dropping an undersized group and
       comparing only the remainder would report a smaller disparity than
       reality -- wrong in the direction that hides bias, which is the
       failure mode this whole fix exists to close.
    """
    per_group_positive: Dict[Any, List[bool]] = {}
    per_group_negative: Dict[Any, List[bool]] = {}
    group_totals: Dict[Any, int] = {}
    total_labeled = 0
    total_with_group = 0

    for record in records:
        if group_key not in record or record[group_key] is None:
            continue
        total_with_group += 1
        label = _to_binary(record.get("label"))
        pred = _to_binary(record.get("prediction"))
        if label is None or pred is None:
            continue
        total_labeled += 1
        group = record[group_key]
        group_totals[group] = group_totals.get(group, 0) + 1
        bucket = per_group_positive if label else per_group_negative
        bucket.setdefault(group, []).append(pred)

    coverage = {
        "labeled_records": total_labeled,
        "total_group_records": total_with_group,
        "label_coverage": (total_labeled / total_with_group) if total_with_group else 0.0,
    }

    if total_labeled < _MIN_LABELED_TOTAL:
        return None, [], {
            **coverage,
            "reason": f"fewer than {_MIN_LABELED_TOTAL} labeled records ({total_labeled})",
        }

    if len(group_totals) < _MIN_GROUPS_REQUIRED:
        return None, [], {**coverage, "reason": "fewer than 2 protected groups had labeled data"}

    undersized = {str(g): c for g, c in group_totals.items() if c < _MIN_LABELED_PER_GROUP}
    if undersized:
        return None, [], {
            **coverage,
            "reason": f"group(s) below minimum of {_MIN_LABELED_PER_GROUP} labeled records: {undersized}",
        }

    tpr = _group_positive_rates(per_group_positive)
    fpr = _group_positive_rates(per_group_negative)

    if len(tpr) < _MIN_GROUPS_REQUIRED and len(fpr) < _MIN_GROUPS_REQUIRED:
        return None, [], {
            **coverage,
            "reason": "fewer than 2 groups had any positive- or negative-label examples",
        }

    tpr_gap = (max(tpr.values()) - min(tpr.values())) if len(tpr) >= _MIN_GROUPS_REQUIRED else 0.0
    fpr_gap = (max(fpr.values()) - min(fpr.values())) if len(fpr) >= _MIN_GROUPS_REQUIRED else 0.0
    disparity = max(tpr_gap, fpr_gap)

    if tpr_gap >= fpr_gap and len(tpr) >= _MIN_GROUPS_REQUIRED:
        affected = [min(tpr, key=tpr.get)]
    elif len(fpr) >= _MIN_GROUPS_REQUIRED:
        affected = [max(fpr, key=fpr.get)]
    else:
        affected = []

    return max(0.0, 1.0 - disparity), affected, coverage


def _calibration_score(
    records: List[Dict[str, Any]],
    group_key: str,
) -> Tuple[Optional[float], List[Any], Dict[str, Any]]:
    """``1 - max pairwise difference`` in per-group calibration error,
    where a group's calibration error is
    ``|mean(predicted score) - mean(actual outcome)|``.

    A well-calibrated, fair model has similar calibration error across
    protected groups; a large gap means the model's confidence means
    something different depending on group membership. The predicted score
    is read from an optional ``"score"`` key (falling back to
    ``"prediction"`` if absent, so a caller doesn't need both).

    Same partial-labels handling and guard rails as `_equalized_odds_score`
    (see its docstring): computes on the labeled subset, reports coverage,
    and any protected group below `_MIN_LABELED_PER_GROUP` labeled records
    makes the whole metric not_computable rather than being dropped from
    the comparison.
    """
    per_group_scores: Dict[Any, List[float]] = {}
    per_group_labels: Dict[Any, List[float]] = {}
    group_totals: Dict[Any, int] = {}
    total_labeled = 0
    total_with_group = 0

    for record in records:
        if group_key not in record or record[group_key] is None:
            continue
        total_with_group += 1
        label = _to_binary(record.get("label"))
        score_value = _to_score(record.get("score", record.get("prediction")))
        if label is None or score_value is None:
            continue
        total_labeled += 1
        group = record[group_key]
        group_totals[group] = group_totals.get(group, 0) + 1
        per_group_scores.setdefault(group, []).append(score_value)
        per_group_labels.setdefault(group, []).append(1.0 if label else 0.0)

    coverage = {
        "labeled_records": total_labeled,
        "total_group_records": total_with_group,
        "label_coverage": (total_labeled / total_with_group) if total_with_group else 0.0,
    }

    if total_labeled < _MIN_LABELED_TOTAL:
        return None, [], {
            **coverage,
            "reason": f"fewer than {_MIN_LABELED_TOTAL} labeled records ({total_labeled})",
        }

    if len(group_totals) < _MIN_GROUPS_REQUIRED:
        return None, [], {**coverage, "reason": "fewer than 2 protected groups had labeled data"}

    undersized = {str(g): c for g, c in group_totals.items() if c < _MIN_LABELED_PER_GROUP}
    if undersized:
        return None, [], {
            **coverage,
            "reason": f"group(s) below minimum of {_MIN_LABELED_PER_GROUP} labeled records: {undersized}",
        }

    errors = {
        group: abs(
            sum(scores) / len(scores) - sum(per_group_labels[group]) / len(per_group_labels[group])
        )
        for group, scores in per_group_scores.items()
    }
    disparity = max(errors.values()) - min(errors.values())
    worst_group = max(errors, key=errors.get)
    return max(0.0, 1.0 - disparity), [worst_group], coverage


def _compute_metric_for_attribute(
    metric: BiasMetric,
    predictions: List[Dict[str, Any]],
    attr: str,
) -> Tuple[Optional[float], List[Any], Dict[str, Any]]:
    """Dispatch a single protected attribute to its metric implementation."""
    if metric == BiasMetric.DEMOGRAPHIC_PARITY:
        rates = _group_positive_rates(_group_binary_values(predictions, attr, "prediction"))
        return _demographic_parity_score(rates)
    if metric == BiasMetric.DISPARATE_IMPACT:
        rates = _group_positive_rates(_group_binary_values(predictions, attr, "prediction"))
        return _disparate_impact_score(rates)
    if metric == BiasMetric.EQUALIZED_ODDS:
        return _equalized_odds_score(predictions, attr)
    if metric == BiasMetric.CALIBRATION:
        return _calibration_score(predictions, attr)
    return None, [], {"reason": f"unsupported metric {metric}"}


class DriftDetectionEngine:
    """Engine for detecting model drift."""

    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or get_model_registry()
        self.drift_history: Dict[str, List[ModelDrift]] = {}

    def detect_drift(
        self,
        model_id: str,
        current_data: List[Dict[str, Any]],
        baseline_data: List[Dict[str, Any]],
    ) -> ModelDrift:
        """Detect drift in a model."""
        drift_id = str(uuid4())

        drift_score, extra_details = self._analyze_drift(current_data, baseline_data)

        # `computable=False` (set only when literally zero features could be
        # scored) gets its own severity rather than pretending drift_score's
        # placeholder 0.0 is a real "no drift" reading -- 0.0 already means
        # "clean" downstream (get_compliance_status, severity buckets), so a
        # not-computable 0.0 would be a false pass, the drift mirror image
        # of the bias not-computable bug.
        if extra_details.get("computable") is False:
            severity = "UNKNOWN"
        elif drift_score > 0.8:
            severity = "CRITICAL"
        elif drift_score > 0.6:
            severity = "HIGH"
        elif drift_score > 0.4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        drift_type = DriftType.DATA_DRIFT

        details: Dict[str, Any] = {
            "current_size": len(current_data),
            "baseline_size": len(baseline_data),
            "method": "population_stability_index",
        }
        details.update(extra_details)

        drift = ModelDrift(
            drift_id=drift_id,
            model_id=model_id,
            drift_type=drift_type,
            drift_score=drift_score,
            severity=severity,
            details=details,
        )

        if model_id not in self.drift_history:
            self.drift_history[model_id] = []
        self.drift_history[model_id].append(drift)

        return drift

    def _calculate_drift_score(
        self,
        current_data: List[Dict[str, Any]],
        baseline_data: List[Dict[str, Any]],
    ) -> float:
        """Calculate the aggregate ``[0, 1]`` drift score between datasets.

        Kept as a thin wrapper around `_analyze_drift` (which also returns
        the per-feature breakdown used by `detect_drift`'s audit details)
        for backward compatibility with callers/tests that only want the
        scalar score.
        """
        score, _ = self._analyze_drift(current_data, baseline_data)
        return score

    def _analyze_drift(
        self,
        current_data: List[Dict[str, Any]],
        baseline_data: List[Dict[str, Any]],
    ) -> Tuple[float, Dict[str, Any]]:
        """Compare ``current_data`` against ``baseline_data`` feature by
        feature and return ``(drift_score, details)``.

        Method
        ------
        Each feature (dict key) shared by both datasets is compared with the
        Population Stability Index (see `_numeric_psi`/`_categorical_psi`),
        mapped onto this engine's ``[0, 1]`` scale via `_psi_to_drift_score`.
        The overall score is the *maximum* per-feature score, so a single
        badly-drifted feature is enough to raise the alert level; the full
        per-feature breakdown is returned in ``details["feature_scores"]``
        so the audit trail says exactly which feature(s) moved.

        For numeric features with at least 2 valid observations on both
        sides, a two-sample Kolmogorov-Smirnov test (`scipy.stats.ks_2samp`)
        is also computed and included per-feature as supplementary evidence
        (``ks_statistic``, ``ks_p_value``). It is deliberately **not**
        blended into the score: PSI answers "how much has the distribution
        shifted, in a monitoring-relevant sense" (a magnitude), while KS
        answers "are these plausibly samples from the same distribution" (a
        hypothesis test) -- mixing a p-value into a magnitude score isn't a
        principled operation, so KS is reported alongside PSI for an
        auditor to read, not folded into the number that drives severity.

        Schema mismatch
        ----------------
        If the two datasets don't share the same set of feature keys, the
        datasets aren't comparable distribution-for-distribution; this is
        reported as maximum drift (``1.0``) rather than silently scoring
        just the overlapping keys.

        Not computable
        --------------
        A feature is "not computable" (``insufficient_data``) when there is
        no usable data to compare -- see `_numeric_psi`/`_categorical_psi`
        for the exact conditions. Two levels of this are surfaced:

        - Every feature not computable -> the overall result is not
          computable at all: ``details["computable"] = False`` (checked
          explicitly by `detect_drift`/`get_compliance_status`, never
          inferred from a bare ``drift_score`` of 0.0).
        - Some features computable, some not -> the score aggregates over
          the scorable subset only, and ``details["feature_coverage"]``
          reports how much of the schema that subset represents. Below
          `_MIN_FEATURE_COVERAGE` (50%), ``details["low_feature_coverage"]``
          is set so a caller building a score from less than half the
          tracked features doesn't trust it as a full monitoring signal.

        Empty ``current_data``/``baseline_data`` (no records at all) is
        treated as before this fix: ``(0.0, {})``. That specific case
        predates -- and is unrelated to -- the random-score bug this
        function replaces, so it is intentionally left as-is.
        """
        if not current_data or not baseline_data:
            return 0.0, {}

        current_keys: set = set()
        for item in current_data:
            current_keys.update(item.keys())

        baseline_keys: set = set()
        for item in baseline_data:
            baseline_keys.update(item.keys())

        if current_keys != baseline_keys:
            missing_keys = sorted(baseline_keys - current_keys)
            extra_keys = sorted(current_keys - baseline_keys)
            return 1.0, {
                "schema_mismatch": True,
                "missing_keys": missing_keys,
                "extra_keys": extra_keys,
            }

        feature_scores: Dict[str, Any] = {}
        computable_scores: List[float] = []
        skipped_features: List[Dict[str, str]] = []

        for key in sorted(current_keys):
            baseline_vals = [item.get(key) for item in baseline_data if key in item]
            current_vals = [item.get(key) for item in current_data if key in item]
            # NaN must count as "missing" here too, not as evidence the
            # feature is non-numeric -- otherwise a single NaN among
            # otherwise-numeric values misclassifies the whole feature as
            # categorical, where it would then be scored as an "unseen"
            # category instead of being excluded (see `_is_missing`).
            present_baseline = [v for v in baseline_vals if not _is_missing(v)]
            is_numeric = bool(present_baseline) and all(_is_number(v) for v in present_baseline)

            psi, reason = (
                _numeric_psi(baseline_vals, current_vals)
                if is_numeric
                else _categorical_psi(baseline_vals, current_vals)
            )

            entry: Dict[str, Any] = {"type": "numeric" if is_numeric else "categorical"}
            if psi is None:
                entry["status"] = "insufficient_data"
                entry["reason"] = reason
                skipped_features.append({"feature": key, "reason": reason})
            else:
                entry["status"] = "ok"
                entry["psi"] = round(psi, 6)
                feature_score = _psi_to_drift_score(psi)
                entry["score"] = round(feature_score, 6)
                computable_scores.append(feature_score)

                if is_numeric:
                    baseline_arr = np.array([v for v in baseline_vals if _is_number(v)], dtype=float)
                    current_arr = np.array([v for v in current_vals if _is_number(v)], dtype=float)
                    if baseline_arr.size >= 2 and current_arr.size >= 2:
                        ks_stat, ks_pvalue = scipy_stats.ks_2samp(baseline_arr, current_arr)
                        entry["ks_statistic"] = round(float(ks_stat), 6)
                        entry["ks_p_value"] = round(float(ks_pvalue), 6)

            feature_scores[key] = entry

        total_features = len(current_keys)
        scorable_features = len(computable_scores)

        details: Dict[str, Any] = {
            "feature_scores": feature_scores,
            "feature_coverage": {
                "scorable_features": scorable_features,
                "total_features": total_features,
                "skipped_features": skipped_features,
            },
        }

        if not computable_scores:
            details["computable"] = False
            details["reason"] = "no shared feature had usable (non-null, present-on-both-sides) data to compare"
            return 0.0, details

        coverage_fraction = scorable_features / total_features if total_features else 0.0
        details["low_feature_coverage"] = coverage_fraction < _MIN_FEATURE_COVERAGE

        return max(computable_scores), details

    def get_drift_history(self, model_id: str) -> List[ModelDrift]:
        """Get drift history for a model."""
        return self.drift_history.get(model_id, [])

    def get_latest_drift(self, model_id: str) -> Optional[ModelDrift]:
        """Get the latest drift detection."""
        history = self.drift_history.get(model_id, [])
        return history[-1] if history else None


class BiasDetectionEngine:
    """Engine for detecting model bias."""

    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or get_model_registry()
        self.reports: Dict[str, List[BiasReport]] = {}

    def detect_bias(
        self,
        model_id: str,
        predictions: List[Dict[str, Any]],
        protected_attributes: List[str],
    ) -> List[BiasReport]:
        """Detect bias in model predictions."""
        reports = []

        for metric in BiasMetric:
            report = self._evaluate_metric(
                model_id=model_id,
                metric=metric,
                predictions=predictions,
                protected_attributes=protected_attributes,
            )
            reports.append(report)

            if model_id not in self.reports:
                self.reports[model_id] = []
            self.reports[model_id].append(report)

        return reports

    def _evaluate_metric(
        self,
        model_id: str,
        metric: BiasMetric,
        predictions: List[Dict[str, Any]],
        protected_attributes: List[str],
    ) -> BiasReport:
        """Evaluate a specific bias metric across every protected attribute
        in `protected_attributes`, using the record-level fields on each
        item in `predictions`:

            "prediction"           required. Model's binary decision (or a
                                    continuous score, thresholded at 0.5 --
                                    see `_to_binary`).
            <protected attribute>  required per attribute being evaluated,
                                    e.g. "gender": "F", looked up by name
                                    from `protected_attributes`.
            "label"                 optional ground truth, required only
                                    for EQUALIZED_ODDS / CALIBRATION (see
                                    `_equalized_odds_score`/
                                    `_calibration_score` for the partial-
                                    labels rule).
            "score"                 optional continuous predicted
                                    probability for CALIBRATION; falls back
                                    to "prediction" if absent.

        The final score is the worst (lowest = least fair) result across
        every protected attribute that was computable, since a model that
        is fair on one attribute but not another is still not compliant
        overall. If not a single protected attribute could be evaluated
        (too little data, or -- for EQUALIZED_ODDS/CALIBRATION -- no
        ground-truth labels), the report is ``status="not_computable"``
        with ``score=None``/``is_fair=None`` rather than a fabricated
        number: an unmeasured metric must never look identical to a
        measured, failing one to anything reading the report (see
        `BiasReport`).
        """
        threshold = _BIAS_THRESHOLD
        per_attr: List[Tuple[str, float, List[Any], Dict[str, Any]]] = []
        skipped: Dict[str, Dict[str, Any]] = {}

        for attr in protected_attributes:
            score, groups, details = _compute_metric_for_attribute(metric, predictions, attr)
            if score is None:
                skipped[attr] = details
            else:
                per_attr.append((attr, score, groups, details))

        if not per_attr:
            reason = (
                "no protected attributes supplied"
                if not protected_attributes
                else "no protected attribute had enough usable data to evaluate this metric"
            )
            return BiasReport(
                report_id=str(uuid4()),
                model_id=model_id,
                metric=metric,
                score=None,
                threshold=threshold,
                is_fair=None,
                affected_groups=[],
                status="not_computable",
                details={"reason": reason, "skipped_attributes": skipped},
            )

        attr, score, groups, details = min(per_attr, key=lambda item: item[1])
        is_fair = score >= threshold
        affected = [] if is_fair else ([f"{attr}:{group}" for group in groups] if groups else [attr])

        report_details = dict(details)
        report_details["evaluated_attribute"] = attr
        if skipped:
            report_details["skipped_attributes"] = skipped

        return BiasReport(
            report_id=str(uuid4()),
            model_id=model_id,
            metric=metric,
            score=score,
            threshold=threshold,
            is_fair=is_fair,
            affected_groups=affected,
            status="computed",
            details=report_details,
        )

    def get_bias_reports(self, model_id: str) -> List[BiasReport]:
        """Get all bias reports for a model."""
        return self.reports.get(model_id, [])

    def get_latest_reports(self, model_id: str) -> List[BiasReport]:
        """Get latest bias reports for a model."""
        reports = self.reports.get(model_id, [])
        latest_by_metric = {}

        for report in reports:
            if report.metric not in latest_by_metric:
                latest_by_metric[report.metric] = report

        return list(latest_by_metric.values())


class ExplainabilityEngine:
    """Engine for model explainability."""

    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or get_model_registry()
        self.explanations: Dict[str, List[ModelExplanation]] = {}

    def explain_prediction(
        self,
        model_id: str,
        prediction_id: str,
        input_features: Dict[str, Any],
    ) -> ModelExplanation:
        """Generate explanation for a prediction."""
        feature_importance = self._calculate_feature_importance(input_features)

        explanation = ModelExplanation(
            explanation_id=str(uuid4()),
            model_id=model_id,
            prediction_id=prediction_id,
            feature_importance=feature_importance,
            explanation_method="SHAP",
            confidence=random.uniform(0.7, 0.99),
        )

        if model_id not in self.explanations:
            self.explanations[model_id] = []
        self.explanations[model_id].append(explanation)

        return explanation

    def _calculate_feature_importance(
        self,
        input_features: Dict[str, Any],
    ) -> Dict[str, float]:
        """Calculate feature importance."""
        importance = {}
        total = sum(abs(v) if isinstance(v, (int, float)) else 1 for v in input_features.values())

        for key, value in input_features.items():
            if isinstance(value, (int, float)):
                importance[key] = abs(value) / max(1, total)
            else:
                importance[key] = 1.0 / max(1, len(input_features))

        return importance

    def get_explanation(self, explanation_id: str) -> Optional[ModelExplanation]:
        """Get an explanation by ID."""
        for explanations in self.explanations.values():
            for exp in explanations:
                if exp.explanation_id == explanation_id:
                    return exp
        return None


class AIGovernanceEngine:
    """Main AI governance engine."""

    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or get_model_registry()
        self.drift_engine = DriftDetectionEngine(registry)
        self.bias_engine = BiasDetectionEngine(registry)
        self.explainability_engine = ExplainabilityEngine(registry)
        self.audit_log: List[AuditRecord] = []

    def log_action(
        self,
        model_id: str,
        action: str,
        user: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Log an audit action."""
        record = AuditRecord(
            audit_id=str(uuid4()),
            model_id=model_id,
            action=action,
            user=user,
            details=details or {},
        )
        self.audit_log.append(record)
        return record

    def get_audit_log(
        self,
        model_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditRecord]:
        """Get audit log entries."""
        if model_id:
            entries = [r for r in self.audit_log if r.model_id == model_id]
        else:
            entries = self.audit_log

        return entries[-limit:]

    def get_compliance_status(self, model_id: str) -> Dict[str, Any]:
        """Get compliance status for a model.

        Not-computable results (drift or bias) are never treated as "no
        finding" -- they are excluded from the numeric contributions they
        would otherwise make and are instead surfaced through dedicated
        keys so a reviewer can see what could not be verified, and
        `requires_review` is forced True whenever anything couldn't be
        verified, on top of the usual score-threshold trigger.
        """
        model = self.registry.get_model(model_id)
        if not model:
            return {"error": "Model not found"}

        drift = self.drift_engine.get_latest_drift(model_id)
        bias_reports = self.bias_engine.get_latest_reports(model_id)

        compliance_score = 1.0

        drift_not_computable = bool(drift and drift.details.get("computable") is False)
        drift_low_coverage = bool(
            drift and not drift_not_computable and drift.details.get("low_feature_coverage") is True
        )

        if drift_not_computable:
            # We could not verify whether the model has drifted at all;
            # treat that at least as seriously as a confirmed HIGH/CRITICAL
            # finding rather than leaving compliance_score at a "clean" 1.0
            # -- the drift mirror image of the bias not-computable bug,
            # where 0.0 means "no drift" and so would otherwise be a false
            # pass. Mutually exclusive with the severity-based penalty
            # below (if/elif), and severity is forced to "UNKNOWN" (never
            # "HIGH"/"CRITICAL") whenever this branch is taken, so the two
            # penalties can never stack for the same drift result.
            compliance_score -= 0.3
        elif drift and drift.severity in ["HIGH", "CRITICAL"]:
            compliance_score -= 0.3

        computed_bias = [r for r in bias_reports if r.status == "computed"]
        skipped_bias = [r for r in bias_reports if r.status == "not_computable"]
        biased_metrics = [r for r in computed_bias if not r.is_fair]
        compliance_score -= len(biased_metrics) * 0.1

        return {
            "model_id": model_id,
            "model_name": model.name,
            "status": model.status.value,
            "compliance_score": max(0.0, compliance_score),
            "drift_detected": drift is not None,
            "drift_severity": drift.severity if drift else "NONE",
            "drift_not_computable": (
                {"reason": drift.details.get("reason")} if drift_not_computable else None
            ),
            "drift_low_feature_coverage": (
                {
                    "scorable_features": drift.details.get("feature_coverage", {}).get("scorable_features"),
                    "total_features": drift.details.get("feature_coverage", {}).get("total_features"),
                }
                if drift_low_coverage
                else None
            ),
            "bias_issues": len(biased_metrics),
            "bias_metrics_skipped": [
                {"metric": r.metric.value, "reason": r.details.get("reason")}
                for r in skipped_bias
            ],
            "requires_review": (
                compliance_score < 0.7
                or bool(skipped_bias)
                or drift_not_computable
                or drift_low_coverage
            ),
        }


def get_governance_engine() -> AIGovernanceEngine:
    """Get the global governance engine instance."""
    global _governance_engine
    if _governance_engine is None:
        _governance_engine = AIGovernanceEngine()
    return _governance_engine


_governance_engine: Optional[AIGovernanceEngine] = None
