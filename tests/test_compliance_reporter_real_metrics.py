"""Tests that compliance reporting is measured from stored decisions.

The reporter previously drew every metric -- decision volumes, approval rate,
error rates, and the disparate impact ratio -- from ``random``. These tests
pin the figures to the traces actually recorded.
"""

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from src.explainable_ai import compliance_reporter as compliance_reporter_module
from src.explainable_ai.compliance_reporter import ComplianceReporter
from src.explainable_ai.models import (
    BiasMetric,
    ComplianceFramework,
    DecisionTrace,
    Explanation,
    ExplanationType,
)
from src.explainable_ai.store import ExplainableAIStore


@pytest.fixture
def store():
    return ExplainableAIStore()


@pytest.fixture
def reporter(store):
    return ComplianceReporter(store=store)


def make_trace(
    store,
    decision_id,
    decision="approve",
    *,
    model_id="model_1",
    features=None,
    processing_ms=100.0,
    age_days=0,
):
    trace = DecisionTrace(
        decision_id=decision_id,
        model_id=model_id,
        model_version="v2.1",
        model_name="Fraud Model",
        input_features=features or {},
        output_decision=decision,
        output_score=0.5,
        processing_time_ms=processing_ms,
        timestamp=datetime.now(timezone.utc) - timedelta(days=age_days),
    )
    return store.store_trace(trace)


class TestDeterminism:
    """The module must not manufacture regulatory figures."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(compliance_reporter_module)
        assert "import random" not in source

    def test_repeated_reports_over_same_data_agree(self, store, reporter):
        for i in range(6):
            make_trace(store, f"d{i}", "approve" if i < 4 else "decline")

        now = datetime.now(timezone.utc)
        window = (now - timedelta(days=1), now + timedelta(days=1))

        first = reporter.generate_compliance_report(
            "fair_lending", ComplianceFramework.FAIR_LENDING, *window,
        )
        second = reporter.generate_compliance_report(
            "fair_lending", ComplianceFramework.FAIR_LENDING, *window,
        )

        assert first.metrics == second.metrics

    def test_repeated_bias_analyses_agree(self, store, reporter):
        for i in range(8):
            make_trace(
                store, f"d{i}", "approve" if i % 2 else "decline",
                features={"gender": "a" if i < 4 else "b"},
            )

        first = reporter.analyze_bias("model_1", "gender", BiasMetric.DISPARATE_IMPACT)
        second = reporter.analyze_bias("model_1", "gender", BiasMetric.DISPARATE_IMPACT)

        assert first.value == second.value
        assert first.affected_groups == second.affected_groups


class TestComplianceMetrics:
    """Metrics are counted from traces inside the reporting period."""

    def _report(self, reporter, days=1):
        now = datetime.now(timezone.utc)
        return reporter.generate_compliance_report(
            report_type="fair_lending",
            framework=ComplianceFramework.FAIR_LENDING,
            period_start=now - timedelta(days=days),
            period_end=now + timedelta(days=1),
        )

    def test_counts_match_stored_traces(self, store, reporter):
        for i in range(10):
            make_trace(store, f"d{i}", "approve" if i < 7 else "decline")

        metrics = self._report(reporter).metrics

        assert metrics["total_decisions"] == 10
        assert metrics["fraud_decisions"] == 3
        assert metrics["approval_rate"] == pytest.approx(0.7)
        assert metrics["model_version"] == "v2.1"

    def test_average_processing_time_is_the_mean(self, store, reporter):
        make_trace(store, "d1", processing_ms=50.0)
        make_trace(store, "d2", processing_ms=150.0)

        metrics = self._report(reporter).metrics

        assert metrics["average_processing_time_ms"] == pytest.approx(100.0)

    def test_traces_outside_the_period_are_excluded(self, store, reporter):
        make_trace(store, "recent")
        make_trace(store, "old", age_days=30)

        metrics = self._report(reporter, days=1).metrics

        assert metrics["total_decisions"] == 1

    def test_empty_period_reports_no_data_rather_than_figures(self, reporter):
        metrics = self._report(reporter).metrics

        assert metrics["total_decisions"] == 0
        assert metrics["approval_rate"] is None
        assert metrics["insufficient_data"] is True

    def test_empty_period_raises_a_finding(self, reporter):
        codes = {f["code"] for f in self._report(reporter).findings}

        assert "NO_DECISIONS_RECORDED" in codes

    def test_error_rates_unavailable_without_confirmed_outcomes(self, store, reporter):
        for i in range(4):
            make_trace(store, f"d{i}")

        report = self._report(reporter)

        assert report.metrics["false_positive_rate"] is None
        assert "NO_CONFIRMED_OUTCOMES" in {f["code"] for f in report.findings}

    def test_error_rates_computed_from_confirmed_outcomes(self, store, reporter):
        # Two legitimate decisions, one of them wrongly declined -> FPR 0.5.
        make_trace(store, "l1", "approve", features={"confirmed_fraud": False})
        make_trace(store, "l2", "decline", features={"confirmed_fraud": False})
        # Two frauds, one of them let through -> FNR 0.5.
        make_trace(store, "f1", "decline", features={"confirmed_fraud": True})
        make_trace(store, "f2", "approve", features={"confirmed_fraud": True})

        metrics = self._report(reporter).metrics

        assert metrics["false_positive_rate"] == pytest.approx(0.5)
        assert metrics["false_negative_rate"] == pytest.approx(0.5)
        assert metrics["labelled_decisions"] == 4

    def test_compliance_score_is_explanation_coverage(self, store, reporter):
        make_trace(store, "explained")
        make_trace(store, "unexplained")
        store.store_explanation(Explanation(
            decision_id="explained",
            explanation_type=ExplanationType.SHAP,
            model_id="model_1",
            model_version="v2.1",
            summary="explained",
        ))

        metrics = self._report(reporter).metrics

        assert metrics["compliance_score"] == pytest.approx(0.5)
        assert metrics["explained_decisions"] == 1


class TestBiasAnalysis:
    """The 80% rule is applied to recorded selection rates."""

    def test_disparate_impact_ratio_from_selection_rates(self, store, reporter):
        # Group "a": 4 of 4 approved. Group "b": 2 of 5 approved -> ratio 0.4.
        for i in range(4):
            make_trace(store, f"a{i}", "approve", features={"gender": "a"})
        for i in range(5):
            make_trace(
                store, f"b{i}", "approve" if i < 2 else "decline",
                features={"gender": "b"},
            )

        analysis = reporter.analyze_bias(
            "model_1", "gender", BiasMetric.DISPARATE_IMPACT,
        )

        assert analysis.value == pytest.approx(0.4)
        assert analysis.compliant is False
        assert analysis.affected_groups == ["b"]
        assert analysis.details["sample_size"] == 9

    def test_even_treatment_is_compliant(self, store, reporter):
        for group in ("a", "b"):
            for i in range(4):
                make_trace(
                    store, f"{group}{i}", "approve" if i < 3 else "decline",
                    features={"gender": group},
                )

        analysis = reporter.analyze_bias(
            "model_1", "gender", BiasMetric.DISPARATE_IMPACT,
        )

        assert analysis.value == pytest.approx(1.0)
        assert analysis.compliant is True
        assert analysis.affected_groups == []

    def test_single_group_fails_closed(self, store, reporter):
        for i in range(4):
            make_trace(store, f"a{i}", "approve", features={"gender": "a"})

        analysis = reporter.analyze_bias(
            "model_1", "gender", BiasMetric.DISPARATE_IMPACT,
        )

        assert analysis.compliant is False
        assert analysis.details["insufficient_data"] is True

    def test_other_models_decisions_are_not_mixed_in(self, store, reporter):
        for i in range(4):
            make_trace(store, f"a{i}", "approve", features={"gender": "a"})
        for i in range(4):
            make_trace(
                store, f"o{i}", "decline",
                model_id="other_model", features={"gender": "b"},
            )

        analysis = reporter.analyze_bias(
            "model_1", "gender", BiasMetric.DISPARATE_IMPACT,
        )

        assert analysis.details["sample_size"] == 4
        assert analysis.details["insufficient_data"] is True
