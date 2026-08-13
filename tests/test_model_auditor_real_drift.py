"""Tests that model audits measure what they report.

Drift scores were random draws, the training data integrity hash was taken
over a random integer, and every audit was auto-approved regardless of what
its checks found.
"""

import inspect

import pytest

from src.explainable_ai import model_auditor as model_auditor_module
from src.explainable_ai.model_auditor import ModelAuditor
from src.explainable_ai.models import ModelAuditStatus
from src.explainable_ai.store import ExplainableAIStore


@pytest.fixture
def store():
    return ExplainableAIStore()


@pytest.fixture
def auditor(store):
    return ModelAuditor(store=store)


def sample(amount=10.0, score=0.5, n=20):
    return [{"amount": amount, "age": 30, "score": score} for _ in range(n)]


def statuses(audit):
    return {f["check"]: f["status"] for f in audit.findings}


class TestDeterminism:
    """Audit figures must be measured, not drawn."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(model_auditor_module)
        assert "import random" not in source

    def test_repeated_drift_detection_agrees(self, auditor):
        reference, current = sample(), sample(amount=12.0)

        first = auditor.detect_drift("m1", reference, current)
        second = auditor.detect_drift("m1", reference, current)

        assert first["feature_drift_score"] == second["feature_drift_score"]


class TestDriftDetection:
    """Drift is computed from the two samples supplied."""

    def test_identical_samples_show_no_drift(self, auditor):
        data = sample()

        result = auditor.detect_drift("m1", data, list(data))

        assert result["feature_drift_score"] == 0.0
        assert result["drift_detected"] is False

    def test_shifted_features_show_drift(self, auditor):
        result = auditor.detect_drift("m1", sample(), sample(amount=1000.0))

        assert result["feature_drift_score"] > 0
        assert result["drift_detected"] is True
        assert result["recommendation"] == "Retrain model"

    def test_larger_shift_scores_higher(self, auditor):
        reference = sample()

        small = auditor.detect_drift("m1", reference, sample(amount=11.0))
        large = auditor.detect_drift("m1", reference, sample(amount=500.0))

        assert large["feature_drift_score"] > small["feature_drift_score"]

    def test_performance_drift_reads_the_score_field(self, auditor):
        result = auditor.detect_drift("m1", sample(score=0.5), sample(score=1.0))

        assert result["performance_drift_score"] == pytest.approx(1.0)

    def test_performance_drift_is_none_without_scores(self, auditor):
        reference = [{"amount": 1.0} for _ in range(5)]
        current = [{"amount": 1.0} for _ in range(5)]

        assert auditor.detect_drift("m1", reference, current)["performance_drift_score"] is None

    def test_empty_samples_report_insufficient_data(self, auditor):
        result = auditor.detect_drift("m1", [], sample())

        assert result["details"]["insufficient_data"] is True
        assert result["feature_drift_score"] is None
        assert result["drift_detected"] is False

    def test_only_shared_features_are_compared(self, auditor):
        reference = [{"a": 1.0, "only_ref": 5.0} for _ in range(5)]
        current = [{"a": 1.0, "only_cur": 9.0} for _ in range(5)]

        result = auditor.detect_drift("m1", reference, current)

        assert result["details"]["compared_features"] == ["a"]

    def test_non_numeric_fields_are_ignored(self, auditor):
        reference = [{"a": 1.0, "label": "x"} for _ in range(5)]
        current = [{"a": 1.0, "label": "y"} for _ in range(5)]

        result = auditor.detect_drift("m1", reference, current)

        assert result["details"]["compared_features"] == ["a"]
        assert result["feature_drift_score"] == 0.0

    def test_no_shared_numeric_features_is_not_drift(self, auditor):
        reference = [{"a": 1.0} for _ in range(5)]
        current = [{"b": 1.0} for _ in range(5)]

        result = auditor.detect_drift("m1", reference, current)

        assert result["feature_drift_score"] is None
        assert result["drift_detected"] is False


class TestDataHash:
    """The integrity hash describes the data."""

    def test_equal_data_hashes_equally(self, auditor):
        data = sample()

        assert auditor._compute_data_hash(data) == auditor._compute_data_hash(list(data))

    def test_different_data_hashes_differently(self, auditor):
        assert auditor._compute_data_hash(sample()) != auditor._compute_data_hash(
            sample(amount=11.0)
        )

    def test_key_order_does_not_change_the_hash(self, auditor):
        first = [{"a": 1, "b": 2}]
        second = [{"b": 2, "a": 1}]

        assert auditor._compute_data_hash(first) == auditor._compute_data_hash(second)


class TestAuditChecks:
    """Audits record what they verified and what they did not."""

    def test_missing_training_data_is_skipped_not_passed(self, auditor):
        audit = auditor.create_audit("m1", "Model", "v1")
        auditor.start_audit(audit.audit_id)

        assert statuses(audit)["training_data_integrity"] == "skipped"
        assert audit.training_data_hash is None

    def test_supplied_training_data_is_hashed(self, auditor):
        audit = auditor.create_audit("m1", "Model", "v1")
        auditor.start_audit(audit.audit_id, training_data=sample())

        assert statuses(audit)["training_data_integrity"] == "pass"
        assert audit.training_data_hash is not None

    def test_drift_checks_are_skipped_without_samples(self, auditor):
        audit = auditor.create_audit("m1", "Model", "v1")
        auditor.start_audit(audit.audit_id)

        assert statuses(audit)["feature_drift"] == "skipped"
        assert audit.feature_drift_score is None

    def test_drift_checks_pass_on_stable_data(self, auditor):
        audit = auditor.create_audit("m1", "Model", "v1")
        data = sample()
        auditor.start_audit(
            audit.audit_id, reference_data=data, current_data=list(data),
        )

        assert statuses(audit)["feature_drift"] == "pass"
        assert audit.feature_drift_score == 0.0

    def test_drift_raises_a_warning(self, auditor):
        audit = auditor.create_audit("m1", "Model", "v1")
        auditor.start_audit(
            audit.audit_id,
            reference_data=sample(),
            current_data=sample(amount=1000.0),
        )

        assert statuses(audit)["feature_drift"] == "warning"

    def test_bias_check_does_not_claim_a_pass(self, auditor):
        audit = auditor.create_audit("m1", "Model", "v1")
        auditor.start_audit(audit.audit_id)

        # This module runs no bias analysis; it must not report one passing.
        assert statuses(audit)["bias_assessment"] == "skipped"


class TestApproval:
    """An audit with open checks is not approved by the system."""

    def test_audit_with_warnings_is_not_approved(self, auditor):
        audit = auditor.create_audit("m1", "Model", "v1")
        auditor.start_audit(
            audit.audit_id,
            training_data=sample(),
            reference_data=sample(),
            current_data=sample(amount=1000.0),
        )

        assert audit.status != ModelAuditStatus.APPROVED
        assert audit.approved_by is None

    def test_audit_with_unverified_checks_is_not_approved(self, auditor):
        audit = auditor.create_audit("m1", "Model", "v1")
        auditor.start_audit(audit.audit_id)

        assert audit.status != ModelAuditStatus.APPROVED

    def test_completion_is_still_recorded(self, auditor):
        audit = auditor.create_audit("m1", "Model", "v1")
        auditor.start_audit(audit.audit_id)

        assert audit.completed_at is not None

    def test_explicit_approval_still_works(self, auditor):
        audit = auditor.create_audit("m1", "Model", "v1")
        auditor.start_audit(audit.audit_id)

        approved = auditor.approve_audit(audit.audit_id, "risk_officer")

        assert approved.status == ModelAuditStatus.APPROVED
        assert approved.approved_by == "risk_officer"
