"""Regression tests for issue #3198.

``BiasDetectionEngine._evaluate_metric`` and
``DriftDetectionEngine._calculate_drift_score`` used to return
``random.uniform(...)`` instead of computing real statistics, making every
compliance decision non-deterministic. This file covers, per the issue:

1. Determinism: identical input -> byte-identical output, for both engines.
2. Known values: hand-constructed data with a calculable-by-hand answer.
3. Direction: an unfair/drifted input must score strictly worse than a
   fair/stable one (catches an inverted score convention).
4. Sensitivity: shifting a distribution or skewing a group moves the score
   in the correct direction by a meaningful amount.
5. Edge cases: empty inputs, a single protected group, a zero-member group,
   all-identical predictions, zero denominators, mismatched array lengths,
   NaN/None values -- plus the not-computable-vs-0.0 guarantees added on
   top of the original scope (a "not computable" result must never look
   like a measured "clean"/"fair" result).
6. API-level: hitting both endpoints twice with an identical payload
   returns identical responses, and an unlabeled payload returns 200 with
   ``score: null`` / ``status: "not_computable"`` rather than a 500.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from src.ai_governance.governance_engine import (
    AIGovernanceEngine,
    BiasDetectionEngine,
    DriftDetectionEngine,
    _MIN_LABELED_PER_GROUP,
    _MIN_LABELED_TOTAL,
)
from src.ai_governance.models import BiasMetric
from src.ai_governance.registry import ModelRegistry


@pytest.fixture
def registry() -> ModelRegistry:
    return ModelRegistry()


@pytest.fixture
def model_id(registry: ModelRegistry) -> str:
    return registry.register_model(name="htgnn", version="1.0.0", model_type="graph")


def _labeled(pred, label, **groups) -> dict:
    record = {"prediction": pred, "label": label}
    record.update(groups)
    return record


# ---------------------------------------------------------------------------
# 1. Determinism
# ---------------------------------------------------------------------------


class TestDriftDeterminism:
    def test_same_input_twice_is_byte_identical(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline = [{"amount": 40.0 + i, "velocity": 1.0 + 0.1 * i} for i in range(20)]
        current = [{"amount": 44.0 + i, "velocity": 1.3 + 0.1 * i} for i in range(20)]

        first = engine._calculate_drift_score(current, baseline)
        second = engine._calculate_drift_score(current, baseline)
        third = engine._calculate_drift_score(list(current), list(baseline))

        assert first == second == third

    def test_detect_drift_repeated_calls_produce_identical_scores(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline = [{"amount": 40.0 + i} for i in range(15)]
        current = [{"amount": 46.0 + i} for i in range(15)]

        scores = {
            engine.detect_drift(model_id, current, baseline).drift_score for _ in range(5)
        }

        assert len(scores) == 1


class TestBiasDeterminism:
    def test_same_input_twice_is_byte_identical(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [
            _labeled(1, 1, gender="M"),
            _labeled(0, 0, gender="M"),
            _labeled(1, 1, gender="F"),
            _labeled(0, 0, gender="F"),
            _labeled(1, 1, gender="F"),
        ]

        first = engine.detect_bias(model_id, predictions, ["gender"])
        second = engine.detect_bias(model_id, list(predictions), ["gender"])

        assert [r.score for r in first] == [r.score for r in second]
        assert [r.is_fair for r in first] == [r.is_fair for r in second]
        assert [r.status for r in first] == [r.status for r in second]


# ---------------------------------------------------------------------------
# 2. Known values
# ---------------------------------------------------------------------------


class TestDriftKnownValues:
    def test_identical_distributions_have_zero_psi(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline = [{"amount": float(i)} for i in range(30)]
        current = [{"amount": float(i)} for i in range(30)]

        drift = engine.detect_drift(model_id, current, baseline)

        assert drift.details["feature_scores"]["amount"]["psi"] == 0.0
        assert drift.drift_score == 0.0
        assert drift.severity == "LOW"

    def test_categorical_identical_frequencies_have_zero_psi(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline = [{"merchant": m} for m in ["acme", "acme", "globex", "initech"]]
        current = [{"merchant": m} for m in ["acme", "acme", "globex", "initech"]]

        drift = engine.detect_drift(model_id, current, baseline)

        assert drift.details["feature_scores"]["merchant"]["psi"] == 0.0


class TestBiasKnownValues:
    def test_equal_positive_rates_are_perfectly_fair(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [
            {"prediction": 1, "gender": "M"}, {"prediction": 0, "gender": "M"},
            {"prediction": 1, "gender": "F"}, {"prediction": 0, "gender": "F"},
        ]

        reports = engine.detect_bias(model_id, predictions, ["gender"])
        by_metric = {r.metric: r for r in reports}

        assert by_metric[BiasMetric.DEMOGRAPHIC_PARITY].score == 1.0
        assert by_metric[BiasMetric.DEMOGRAPHIC_PARITY].is_fair is True
        assert by_metric[BiasMetric.DISPARATE_IMPACT].score == 1.0
        assert by_metric[BiasMetric.DISPARATE_IMPACT].is_fair is True

    def test_80_40_split_gives_disparate_impact_of_exactly_half(self, registry, model_id):
        # Group A: 4/5 positive (0.8). Group B: 2/5 positive (0.4).
        # min(rate)/max(rate) = 0.4 / 0.8 = 0.5 exactly.
        predictions = (
            [{"prediction": 1, "gender": "A"}] * 4 + [{"prediction": 0, "gender": "A"}]
            + [{"prediction": 1, "gender": "B"}] * 2 + [{"prediction": 0, "gender": "B"}] * 3
        )
        engine = BiasDetectionEngine(registry)

        reports = engine.detect_bias(model_id, predictions, ["gender"])
        by_metric = {r.metric: r for r in reports}

        assert by_metric[BiasMetric.DISPARATE_IMPACT].score == pytest.approx(0.5)
        assert by_metric[BiasMetric.DISPARATE_IMPACT].is_fair is False
        # demographic parity: 1 - (0.8 - 0.4) = 0.6
        assert by_metric[BiasMetric.DEMOGRAPHIC_PARITY].score == pytest.approx(0.6)


# ---------------------------------------------------------------------------
# 3. Direction (catches an inverted score convention)
# ---------------------------------------------------------------------------


class TestDriftDirection:
    def test_drifted_input_scores_worse_than_stable_input(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline = [{"amount": float(i)} for i in range(50)]
        stable_current = [{"amount": float(i)} for i in range(50)]
        drifted_current = [{"amount": float(i) + 40} for i in range(50)]

        stable = engine.detect_drift(model_id, stable_current, baseline)
        drifted = engine.detect_drift(model_id, drifted_current, baseline)

        assert drifted.drift_score > stable.drift_score
        assert stable.severity == "LOW"
        assert drifted.severity in ("HIGH", "CRITICAL")


class TestBiasDirection:
    def test_unfair_input_scores_worse_than_fair_input(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        fair = [
            {"prediction": 1, "gender": "M"}, {"prediction": 0, "gender": "M"},
            {"prediction": 1, "gender": "F"}, {"prediction": 0, "gender": "F"},
        ]
        unfair = (
            [{"prediction": 1, "gender": "M"}] * 4
            + [{"prediction": 0, "gender": "F"}] * 4
        )

        fair_reports = {r.metric: r for r in engine.detect_bias(model_id, fair, ["gender"])}
        unfair_reports = {r.metric: r for r in engine.detect_bias(model_id, unfair, ["gender"])}

        assert unfair_reports[BiasMetric.DEMOGRAPHIC_PARITY].score < fair_reports[BiasMetric.DEMOGRAPHIC_PARITY].score
        assert unfair_reports[BiasMetric.DEMOGRAPHIC_PARITY].is_fair is False
        assert fair_reports[BiasMetric.DEMOGRAPHIC_PARITY].is_fair is True


# ---------------------------------------------------------------------------
# 4. Sensitivity
# ---------------------------------------------------------------------------


class TestDriftSensitivity:
    def test_larger_shift_produces_higher_score(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline = [{"amount": float(i)} for i in range(200)]

        small_shift = engine.detect_drift(
            model_id, [{"amount": float(i) + 1} for i in range(200)], baseline
        )
        medium_shift = engine.detect_drift(
            model_id, [{"amount": float(i) + 15} for i in range(200)], baseline
        )
        large_shift = engine.detect_drift(
            model_id, [{"amount": float(i) + 50} for i in range(200)], baseline
        )

        assert small_shift.drift_score < medium_shift.drift_score < large_shift.drift_score


class TestBiasSensitivity:
    def test_skewing_one_group_further_lowers_the_score(self, registry, model_id):
        engine = BiasDetectionEngine(registry)

        mild = [
            {"prediction": 1, "gender": "A"}] * 6 + [{"prediction": 0, "gender": "A"}] * 4 + [
            {"prediction": 1, "gender": "B"}] * 5 + [{"prediction": 0, "gender": "B"}] * 5
        severe = (
            [{"prediction": 1, "gender": "A"}] * 9 + [{"prediction": 0, "gender": "A"}]
            + [{"prediction": 1, "gender": "B"}] + [{"prediction": 0, "gender": "B"}] * 9
        )

        mild_report = next(
            r for r in engine.detect_bias(model_id, mild, ["gender"])
            if r.metric == BiasMetric.DEMOGRAPHIC_PARITY
        )
        severe_report = next(
            r for r in engine.detect_bias(model_id, severe, ["gender"])
            if r.metric == BiasMetric.DEMOGRAPHIC_PARITY
        )

        assert severe_report.score < mild_report.score


# ---------------------------------------------------------------------------
# 5. Edge cases
# ---------------------------------------------------------------------------


class TestDriftEdgeCases:
    def test_empty_inputs(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        assert engine._calculate_drift_score([], []) == 0.0
        assert engine._calculate_drift_score([{"a": 1.0}], []) == 0.0

    def test_current_side_all_null_is_not_computable_for_that_feature(self, registry, model_id):
        # Baseline has a real numeric distribution; current has the key
        # present but every value null -- the mirror image of the
        # all-null-baseline case, and its own not-computable reason.
        engine = DriftDetectionEngine(registry)
        baseline = [{"amount": float(i)} for i in range(10)]
        current = [{"amount": None} for _ in range(10)]

        drift = engine.detect_drift(model_id, current, baseline)

        assert drift.details["feature_scores"]["amount"]["status"] == "insufficient_data"
        assert drift.details["computable"] is False

    def test_categorical_current_side_all_null_is_not_computable(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline = [{"merchant": m} for m in ["acme", "globex"]]
        current = [{"merchant": None}, {"merchant": None}]

        drift = engine.detect_drift(model_id, current, baseline)

        assert drift.details["feature_scores"]["merchant"]["status"] == "insufficient_data"

    def test_mismatched_array_lengths_same_distribution_is_low_drift(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline = [{"a": float(i)} for i in range(100)]
        current = [{"a": float(i)} for i in range(0, 100, 2)]  # half the records, same spread

        drift = engine.detect_drift(model_id, current, baseline)

        assert drift.drift_score == 0.0
        assert drift.severity == "LOW"

    def test_nan_and_none_values_are_excluded_not_crashed_on(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline = [{"a": 1.0}, {"a": 2.0}, {"a": float("nan")}, {"a": None}, {"a": 3.0}]
        current = [{"a": 1.0}, {"a": 2.0}, {"a": 3.0}, {"a": None}]

        drift = engine.detect_drift(model_id, current, baseline)

        assert drift.details["feature_scores"]["a"]["status"] == "ok"
        assert drift.drift_score == 0.0

    def test_categorical_unseen_category_is_not_dropped(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline = [{"merchant": m} for m in (["acme"] * 8 + ["globex"] * 2)]
        current = [{"merchant": m} for m in (["acme"] * 5 + ["globex"] * 2 + ["initech"] * 3)]

        drift = engine.detect_drift(model_id, current, baseline)

        assert drift.details["feature_scores"]["merchant"]["psi"] > 0.0
        assert drift.drift_score > 0.0

    def test_schema_mismatch_is_maximum_drift_not_silent(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        drift = engine.detect_drift(
            model_id, [{"a": 1.0}], [{"a": 1.0, "b": 2.0, "c": 3.0}]
        )
        assert drift.drift_score == 1.0
        assert drift.severity == "CRITICAL"
        assert drift.details["schema_mismatch"] is True

    def test_zero_computable_features_is_not_computable_not_a_false_pass(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        drift = engine.detect_drift(model_id, [{"amount": 10.0}], [{"amount": None}])

        assert drift.details["computable"] is False
        assert drift.severity == "UNKNOWN"

    def test_partial_feature_coverage_reports_the_scorable_subset(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        baseline, current = [], []
        for i in range(10):
            baseline.append({"f1": None, "f2": None, "f3": None, "f4": 1.0 + i, "f5": 2.0 + i})
            current.append({"f1": 5.0, "f2": 5.0, "f3": 5.0, "f4": 1.0 + i, "f5": 2.0 + i})

        drift = engine.detect_drift(model_id, current, baseline)

        coverage = drift.details["feature_coverage"]
        assert coverage["scorable_features"] == 2
        assert coverage["total_features"] == 5
        assert {s["feature"] for s in coverage["skipped_features"]} == {"f1", "f2", "f3"}
        # 2/5 = 40% < the 50% low-coverage threshold
        assert drift.details["low_feature_coverage"] is True
        # But it *was* computable -- not the same as zero-computable-features.
        assert "computable" not in drift.details or drift.details.get("computable") is not False


class TestBiasEdgeCases:
    def test_empty_predictions_is_not_computable(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        reports = engine.detect_bias(model_id, [], ["gender"])
        assert all(r.status == "not_computable" for r in reports)
        assert all(r.score is None for r in reports)

    def test_no_protected_attributes_is_not_computable(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        reports = engine.detect_bias(
            model_id, [{"prediction": 1, "gender": "M"}], []
        )
        assert all(r.status == "not_computable" for r in reports)

    def test_single_protected_group_is_not_computable(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [{"prediction": 1, "gender": "M"}, {"prediction": 0, "gender": "M"}]
        reports = engine.detect_bias(model_id, predictions, ["gender"])

        dp = next(r for r in reports if r.metric == BiasMetric.DEMOGRAPHIC_PARITY)
        assert dp.status == "not_computable"
        assert dp.score is None

    def test_zero_member_group_is_simply_absent_not_a_crash(self, registry, model_id):
        # protected_attributes names an attribute no record actually carries.
        engine = BiasDetectionEngine(registry)
        predictions = [{"prediction": 1}, {"prediction": 0}]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        assert all(r.status == "not_computable" for r in reports)

    def test_all_identical_predictions_is_perfectly_fair(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [{"prediction": 1, "gender": g} for g in ["M", "F", "M", "F"]]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        by_metric = {r.metric: r for r in reports}
        assert by_metric[BiasMetric.DEMOGRAPHIC_PARITY].score == 1.0
        assert by_metric[BiasMetric.DISPARATE_IMPACT].score == 1.0

    def test_all_zero_predictions_avoids_zero_denominator(self, registry, model_id):
        # Disparate impact's min/max ratio would divide by zero if the max
        # group rate were 0; both groups being 0 is defined as parity (1.0).
        engine = BiasDetectionEngine(registry)
        predictions = [{"prediction": 0, "gender": g} for g in ["M", "F", "M", "F"]]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        di = next(r for r in reports if r.metric == BiasMetric.DISPARATE_IMPACT)
        assert di.score == 1.0
        assert di.is_fair is True

    def test_nan_and_none_prediction_values_are_excluded_not_crashed_on(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [
            {"prediction": 1, "gender": "M"}, {"prediction": float("nan"), "gender": "M"},
            {"prediction": None, "gender": "F"}, {"prediction": 1, "gender": "F"},
            {"prediction": 0, "gender": "F"},
        ]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        dp = next(r for r in reports if r.metric == BiasMetric.DEMOGRAPHIC_PARITY)
        assert dp.status == "computed"
        assert 0.0 <= dp.score <= 1.0

    def test_mismatched_field_presence_across_records(self, registry, model_id):
        # Some records omit "gender" entirely, others omit "prediction".
        engine = BiasDetectionEngine(registry)
        predictions = [
            {"prediction": 1, "gender": "M"},
            {"gender": "M"},
            {"prediction": 0, "gender": "F"},
            {"prediction": 1},
        ]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        assert len(reports) == len(list(BiasMetric))


# ---------------------------------------------------------------------------
# Partial labels: guard rails (issue #3198 follow-up)
# ---------------------------------------------------------------------------


class TestBiasPartialLabelsGuard:
    def test_partial_labels_compute_on_the_labeled_subset_and_report_coverage(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [
            _labeled(1, 1, gender="M"), _labeled(0, 0, gender="M"), _labeled(1, 1, gender="M"),
            _labeled(1, 1, gender="F"), _labeled(0, 0, gender="F"), _labeled(1, 1, gender="F"),
            # Unlabeled records: present but must not count toward coverage.
            {"prediction": 1, "gender": "M"},
            {"prediction": 0, "gender": "F"},
        ]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        eq_odds = next(r for r in reports if r.metric == BiasMetric.EQUALIZED_ODDS)

        assert eq_odds.status == "computed"
        assert eq_odds.details["labeled_records"] == 6
        assert eq_odds.details["total_group_records"] == 8
        assert eq_odds.details["label_coverage"] == pytest.approx(0.75)

    def test_boundary_four_labeled_records_is_not_computable(self, registry, model_id):
        assert _MIN_LABELED_TOTAL == 5
        engine = BiasDetectionEngine(registry)
        predictions = [
            _labeled(1, 1, gender="M"), _labeled(0, 0, gender="M"),
            _labeled(1, 1, gender="F"), _labeled(0, 0, gender="F"),
        ]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        eq_odds = next(r for r in reports if r.metric == BiasMetric.EQUALIZED_ODDS)
        assert eq_odds.status == "not_computable"

    def test_boundary_five_labeled_records_is_computable(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [
            _labeled(1, 1, gender="M"), _labeled(0, 0, gender="M"),
            _labeled(1, 1, gender="F"), _labeled(0, 0, gender="F"),
            _labeled(1, 1, gender="M"),
        ]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        eq_odds = next(r for r in reports if r.metric == BiasMetric.EQUALIZED_ODDS)
        assert eq_odds.status == "computed"

    def test_boundary_group_with_one_labeled_record_makes_whole_metric_not_computable(
        self, registry, model_id
    ):
        assert _MIN_LABELED_PER_GROUP == 2
        engine = BiasDetectionEngine(registry)
        # Group "F" has only 1 labeled record; group "M" has plenty.
        predictions = [
            _labeled(1, 1, gender="M"), _labeled(0, 0, gender="M"),
            _labeled(1, 1, gender="M"), _labeled(0, 0, gender="M"),
            _labeled(1, 1, gender="F"),
        ]
        engine_reports = engine.detect_bias(model_id, predictions, ["gender"])
        eq_odds = next(r for r in engine_reports if r.metric == BiasMetric.EQUALIZED_ODDS)
        calibration = next(r for r in engine_reports if r.metric == BiasMetric.CALIBRATION)

        # Must NOT silently exclude "F" and compute a disparity across the
        # survivors -- that would report a smaller disparity than reality.
        assert eq_odds.status == "not_computable"
        assert calibration.status == "not_computable"

    def test_boundary_group_with_two_labeled_records_is_computable(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [
            _labeled(1, 1, gender="M"), _labeled(0, 0, gender="M"),
            _labeled(1, 1, gender="M"), _labeled(0, 0, gender="M"),
            _labeled(1, 1, gender="F"), _labeled(0, 0, gender="F"),
        ]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        eq_odds = next(r for r in reports if r.metric == BiasMetric.EQUALIZED_ODDS)
        assert eq_odds.status == "computed"

    def test_undersized_group_is_named_in_the_reason(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [
            _labeled(1, 1, gender="M"), _labeled(0, 0, gender="M"),
            _labeled(1, 1, gender="M"), _labeled(0, 0, gender="M"),
            _labeled(1, 1, gender="F"),
        ]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        eq_odds = next(r for r in reports if r.metric == BiasMetric.EQUALIZED_ODDS)
        skipped_reason = eq_odds.details["skipped_attributes"]["gender"]["reason"]
        assert "F" in skipped_reason


# ---------------------------------------------------------------------------
# Compliance status: not-computable results must not read as "clean"
# ---------------------------------------------------------------------------


class TestComplianceStatusNotComputable:
    def test_not_computable_drift_forces_review_and_moves_the_score(self, registry, model_id):
        engine = AIGovernanceEngine(registry)
        drift = engine.drift_engine.detect_drift(model_id, [{"amount": 10.0}], [{"amount": None}])

        status = engine.get_compliance_status(model_id)

        # Pins the -0.3 penalty applying exactly once: 1.0 - 0.3 = 0.7, not
        # some other value from a double-counted or missing penalty.
        assert drift.severity == "UNKNOWN"
        assert status["compliance_score"] == pytest.approx(0.7)
        assert status["requires_review"] is True
        assert status["drift_not_computable"] is not None

    def test_not_computable_drift_penalty_does_not_stack_with_severity_penalty(
        self, registry, model_id
    ):
        # Same not-computable drift result, but with severity manually
        # forced to "CRITICAL" after the fact (simulating what would
        # happen if the mutual-exclusion guard in get_compliance_status
        # were ever removed) -- if the two penalties could stack, this
        # would be 1.0 - 0.3 - 0.3 = 0.4 instead of 0.7, since
        # `drift.details["computable"]` is still False.
        engine = AIGovernanceEngine(registry)
        drift = engine.drift_engine.detect_drift(model_id, [{"amount": 10.0}], [{"amount": None}])
        drift.severity = "CRITICAL"

        status = engine.get_compliance_status(model_id)

        assert status["compliance_score"] == pytest.approx(0.7)

    def test_low_feature_coverage_forces_review_even_when_score_looks_clean(self, registry, model_id):
        engine = AIGovernanceEngine(registry)
        baseline, current = [], []
        for i in range(10):
            baseline.append({"f1": None, "f2": None, "f3": None, "f4": 1.0 + i, "f5": 2.0 + i})
            current.append({"f1": 5.0, "f2": 5.0, "f3": 5.0, "f4": 1.0 + i, "f5": 2.0 + i})
        engine.drift_engine.detect_drift(model_id, current, baseline)

        status = engine.get_compliance_status(model_id)

        # Only 2/5 features were scorable and both are stable -> the
        # numeric score alone looks clean (1.0); low_feature_coverage must
        # still force review.
        assert status["compliance_score"] == 1.0
        assert status["requires_review"] is True
        assert status["drift_low_feature_coverage"] == {"scorable_features": 2, "total_features": 5}

    def test_skipped_bias_metrics_force_review(self, registry, model_id):
        engine = AIGovernanceEngine(registry)
        engine.bias_engine.detect_bias(model_id, [], ["gender"])

        status = engine.get_compliance_status(model_id)

        assert status["requires_review"] is True
        assert len(status["bias_metrics_skipped"]) == len(list(BiasMetric))
        assert status["bias_issues"] == 0  # not-computable is not counted as "biased"


# ---------------------------------------------------------------------------
# 6. API-level tests
# ---------------------------------------------------------------------------

_SUPER_ADMIN_KEY = "test-super-admin-key-3198-bias-drift-stats"
_SUPER_ADMIN_HASH = hashlib.sha256(_SUPER_ADMIN_KEY.encode("utf-8")).hexdigest()


def _governance_only_app():
    """A minimal FastAPI app mounting only ``governance_routes.router``.

    ``tests/test_route_module_registration.py`` pins that
    ``governance_routes.py`` is *deliberately* not mounted on the real app
    (``src.api.main``) today -- every ``/api/v1/governance/*`` endpoint
    404s there. That's an existing, intentional, out-of-scope decision for
    this fix; mounting it for real is not part of issue #3198. This
    fixture exercises the router's own request/response handling (real
    Pydantic request models, real `require_role` auth, real
    `to_dict()`-based JSON serialisation) in isolation, which is what
    "hits the API layer" means here without touching that decision or
    the unrelated ``src.api.warfare_routes`` import bug the full app
    currently has.
    """
    from fastapi import FastAPI

    from src.api.governance_routes import router

    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def super_admin_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("AEGIS_ROLE_SUPER_ADMIN", _SUPER_ADMIN_HASH)
    with TestClient(_governance_only_app()) as client:
        yield client


def _headers() -> dict:
    return {"X-API-Key": _SUPER_ADMIN_KEY}


class TestGovernanceAPIEndpoints:
    def test_bias_detect_identical_payload_returns_identical_responses(self, super_admin_client):
        payload = {
            "predictions": [
                {"prediction": 1, "label": 1, "gender": "M"},
                {"prediction": 0, "label": 0, "gender": "M"},
                {"prediction": 1, "label": 1, "gender": "F"},
                {"prediction": 0, "label": 0, "gender": "F"},
            ],
            "protected_attributes": ["gender"],
        }
        first = super_admin_client.post(
            "/api/v1/governance/bias/detect?model_id=model-3198",
            json=payload, headers=_headers(),
        )
        second = super_admin_client.post(
            "/api/v1/governance/bias/detect?model_id=model-3198",
            json=payload, headers=_headers(),
        )

        assert first.status_code == 200
        assert second.status_code == 200
        first_scores = [(r["metric"], r["score"], r["is_fair"]) for r in first.json()["reports"]]
        second_scores = [(r["metric"], r["score"], r["is_fair"]) for r in second.json()["reports"]]
        assert first_scores == second_scores

    def test_drift_detect_identical_payload_returns_identical_responses(self, super_admin_client):
        payload = {
            "current_data": [{"amount": 44.0 + i} for i in range(15)],
            "baseline_data": [{"amount": 40.0 + i} for i in range(15)],
        }
        first = super_admin_client.post(
            "/api/v1/governance/drift/detect?model_id=model-3198",
            json=payload, headers=_headers(),
        )
        second = super_admin_client.post(
            "/api/v1/governance/drift/detect?model_id=model-3198",
            json=payload, headers=_headers(),
        )

        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json()["drift"]["drift_score"] == second.json()["drift"]["drift_score"]
        assert first.json()["drift"]["severity"] == second.json()["drift"]["severity"]

    def test_bias_detect_unlabeled_payload_returns_200_with_null_score(self, super_admin_client):
        # No "label" field anywhere -> EQUALIZED_ODDS/CALIBRATION are
        # not_computable. This must serialise as a normal 200 response
        # with `score: null`, not a 500 -- confirms the route has no
        # `response_model` requiring a non-null float.
        payload = {
            "predictions": [
                {"prediction": 1, "gender": "M"},
                {"prediction": 0, "gender": "F"},
            ],
            "protected_attributes": ["gender"],
        }
        response = super_admin_client.post(
            "/api/v1/governance/bias/detect?model_id=model-3198-unlabeled",
            json=payload, headers=_headers(),
        )

        assert response.status_code == 200
        body = response.json()
        not_computable = [r for r in body["reports"] if r["metric"] in ("EQUALIZED_ODDS", "CALIBRATION")]
        assert not_computable
        for report in not_computable:
            assert report["status"] == "not_computable"
            assert report["score"] is None
            assert report["is_fair"] is None


# ---------------------------------------------------------------------------
# Additional coverage: value-parsing branches and mixed-attribute reporting
# ---------------------------------------------------------------------------


class TestValueParsingBranches:
    def test_boolean_and_string_prediction_values_are_parsed(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [
            {"prediction": True, "gender": "M"}, {"prediction": "no", "gender": "M"},
            {"prediction": False, "gender": "F"}, {"prediction": "yes", "gender": "F"},
        ]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        dp = next(r for r in reports if r.metric == BiasMetric.DEMOGRAPHIC_PARITY)
        assert dp.status == "computed"
        assert dp.score == 1.0  # both groups: 1 positive, 1 negative -> rate 0.5 each

    def test_unparseable_string_prediction_is_excluded_not_crashed_on(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        predictions = [
            {"prediction": "unknown", "gender": "M"}, {"prediction": 1, "gender": "M"},
            {"prediction": 0, "gender": "F"}, {"prediction": 1, "gender": "F"},
        ]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        dp = next(r for r in reports if r.metric == BiasMetric.DEMOGRAPHIC_PARITY)
        assert dp.status == "computed"


class TestEqualizedOddsCalibrationSingleGroupWithLabels(object):
    def test_only_one_group_carries_labels_is_not_computable(self, registry, model_id):
        # Enough *total* labeled records, but every one of them belongs to
        # a single group -- the other group's record has no label, so it
        # never enters the comparison at all.
        engine = BiasDetectionEngine(registry)
        predictions = [
            {"prediction": 1, "label": 1, "gender": "M"},
            {"prediction": 0, "label": 0, "gender": "M"},
            {"prediction": 1, "label": 1, "gender": "M"},
            {"prediction": 0, "label": 0, "gender": "M"},
            {"prediction": 1, "label": 1, "gender": "M"},
            {"prediction": 0, "gender": "F"},
        ]
        reports = engine.detect_bias(model_id, predictions, ["gender"])
        eq_odds = next(r for r in reports if r.metric == BiasMetric.EQUALIZED_ODDS)
        calibration = next(r for r in reports if r.metric == BiasMetric.CALIBRATION)
        assert eq_odds.status == "not_computable"
        assert calibration.status == "not_computable"


class TestMixedComputableAndSkippedAttributes:
    def test_computed_report_still_lists_skipped_attributes(self, registry, model_id):
        # "age" is the same value on every record -> a single group, not
        # computable on its own. "gender" has two groups -> computable.
        # The overall report is "computed" (worst-case across computable
        # attributes) but must still surface that "age" was skipped, and
        # why.
        engine = BiasDetectionEngine(registry)
        predictions = [
            {"prediction": 1, "age": "young", "gender": "M"},
            {"prediction": 0, "age": "young", "gender": "M"},
            {"prediction": 1, "age": "young", "gender": "F"},
            {"prediction": 0, "age": "young", "gender": "F"},
        ]
        reports = engine.detect_bias(model_id, predictions, ["age", "gender"])
        dp = next(r for r in reports if r.metric == BiasMetric.DEMOGRAPHIC_PARITY)

        assert dp.status == "computed"
        assert "age" in dp.details["skipped_attributes"]
        assert dp.details["skipped_attributes"]["age"]["reason"]
