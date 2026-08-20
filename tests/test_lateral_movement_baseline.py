"""
Regression tests for LateralMovementDetector.analyze_account baseline handling.

Primary regression: the baseline used to detect a deviation included the
current sample itself, so a genuine spike inflated the mean and the detection
threshold, masking the very anomaly it should surface. A spike of 0.31 over a
steady baseline of 0.1 was missed (0.31 < 3 * 0.121 with the current sample in
the baseline, but 0.31 > 3 * 0.100 without it).

The detector now compares the current score against the distribution of the
previous history only.
"""

import threading
from collections import defaultdict, deque

import pytest

from src.features.lateral_movement import LateralMovementDetector


def _make_detector(history_size=10, std_multiplier=2.0, spike_multiplier=3.0,
                   risk_penalty=0.25, current_score=0.0):
    """Build a detector via __new__ with only the attrs analyze_account needs."""
    detector = LateralMovementDetector.__new__(LateralMovementDetector)
    detector.use_redis = False
    detector._lock = threading.Lock()
    detector.history_size = history_size
    detector.std_multiplier = std_multiplier
    detector.spike_multiplier = spike_multiplier
    detector.risk_penalty = risk_penalty
    detector.centrality_history = defaultdict(
        lambda: deque(maxlen=history_size)
    )
    detector._calculate_approx_centrality = lambda _account_id: current_score
    return detector


@pytest.fixture
def steady_detector():
    d = _make_detector(current_score=0.1)
    for _ in range(9):
        d.centrality_history["ACC"].append(0.1)
    return d


class TestBaselineExcludesCurrentSample:
    """The current sample must not contaminate its own baseline."""

    def test_masked_spike_now_triggers(self):
        # Regression: this case was missed before the fix.
        d = _make_detector(current_score=0.31)
        for _ in range(9):
            d.centrality_history["ACC"].append(0.1)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is True
        assert risk == pytest.approx(0.25)

    def test_spike_ratio_uses_prior_mean_only(self):
        d = _make_detector(current_score=0.31)
        for _ in range(9):
            d.centrality_history["ACC"].append(0.1)
        # With the current sample excluded the multiplier threshold is
        # 3 * 0.1 = 0.3, so 0.31 must clear it.
        _, flagged = d.analyze_account("ACC")
        assert flagged is True

    def test_steady_state_does_not_trigger(self, steady_detector):
        risk, flagged = steady_detector.analyze_account("ACC")
        assert flagged is False
        assert risk == 0.0

    def test_equal_to_constant_baseline_no_trigger(self):
        d = _make_detector(current_score=0.2)
        for _ in range(9):
            d.centrality_history["ACC"].append(0.2)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is False

    def test_jump_from_constant_baseline_triggers(self):
        d = _make_detector(current_score=0.7)
        for _ in range(9):
            d.centrality_history["ACC"].append(0.2)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is True


class TestTriggerRules:
    """std and multiplier triggers behave independently."""

    def test_std_only_trigger(self):
        # Prior history [0.1,0.1,0.1,0.2,0.2,0.2,0.3]: mean ~0.1714, std ~0.07.
        d = _make_detector(current_score=0.35)
        for v in (0.1, 0.1, 0.1, 0.2, 0.2, 0.2, 0.3):
            d.centrality_history["ACC"].append(v)
        risk, flagged = d.analyze_account("ACC")
        # 0.35 > mean + 2*std, but 0.35 < 3*mean, so only the std rule fires.
        assert flagged is True
        assert risk == pytest.approx(0.25)

    def test_low_score_gate_suppresses_trigger(self):
        # Above both thresholds but <= 0.05 must not flag.
        d = _make_detector(current_score=0.04)
        for _ in range(9):
            d.centrality_history["ACC"].append(0.01)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is False
        assert risk == 0.0

    def test_custom_risk_penalty_returned(self):
        d = _make_detector(current_score=0.31, risk_penalty=0.4)
        for _ in range(9):
            d.centrality_history["ACC"].append(0.1)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is True
        assert risk == pytest.approx(0.4)


class TestInsufficientHistory:
    """Fewer than 3 samples never flags."""

    def test_no_history(self):
        d = _make_detector(current_score=1.0)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is False
        assert risk == 0.0

    def test_one_prior_sample(self):
        d = _make_detector(current_score=1.0)
        d.centrality_history["ACC"].append(0.1)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is False

    def test_two_prior_samples_enough_for_spike(self):
        # Two steady prior samples form a zero-variance baseline, so any
        # jump above it is a deviation and must flag.
        d = _make_detector(current_score=1.0)
        d.centrality_history["ACC"].append(0.1)
        d.centrality_history["ACC"].append(0.1)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is True
        assert risk == pytest.approx(0.25)

    def test_two_prior_samples_steady_state_no_flag(self):
        d = _make_detector(current_score=0.1)
        d.centrality_history["ACC"].append(0.1)
        d.centrality_history["ACC"].append(0.1)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is False
        assert risk == 0.0


class TestHistoryTrimming:
    """The rolling baseline is bounded by history_size."""

    def test_old_samples_drop_out(self):
        d = _make_detector(history_size=10, current_score=0.05)
        # 20 steady samples then a moderate current value.
        for _ in range(20):
            d.centrality_history["ACC"].append(0.1)
        # Only the last 10 (all 0.1) remain, so current 0.05 is not a spike.
        risk, flagged = d.analyze_account("ACC")
        assert flagged is False
        assert risk == 0.0

    def test_trimmed_baseline_still_detects_spike(self):
        d = _make_detector(history_size=10, current_score=0.6)
        for _ in range(20):
            d.centrality_history["ACC"].append(0.1)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is True

    def test_history_length_after_analyze(self):
        d = _make_detector(history_size=10, current_score=0.31)
        for _ in range(9):
            d.centrality_history["ACC"].append(0.1)
        d.analyze_account("ACC")
        assert len(d.centrality_history["ACC"]) == 10


class TestCustomMultipliers:
    """std_multiplier and spike_multiplier are honored.

    Uses the bursty baseline [0, 0, 0, 0, 0.4] (mean 0.08, std 0.16): a
    current score of 0.31 sits above the default 3x-mean threshold (0.24)
    but below both the 5x-mean threshold (0.40) and the std threshold
    (mean + 2*std = 0.40), so only the spike multiplier discriminates.
    """

    BURSTY = [0.0, 0.0, 0.0, 0.0, 0.4]
    CURRENT = 0.31

    def test_high_std_multiplier_raises_std_threshold(self):
        d = _make_detector(current_score=0.35, std_multiplier=5.0)
        for v in (0.1, 0.1, 0.1, 0.2, 0.2, 0.2, 0.3):
            d.centrality_history["ACC"].append(v)
        # mean + 5*std = 0.1714 + 5*0.07 = 0.52 > 0.35 -> no std trigger.
        # 3 * 0.1714 = 0.514 > 0.35 -> no multiplier trigger either.
        risk, flagged = d.analyze_account("ACC")
        assert flagged is False

    def test_low_spike_multiplier_easier_to_trigger(self):
        d = _make_detector(current_score=self.CURRENT, spike_multiplier=2.0)
        for v in self.BURSTY:
            d.centrality_history["ACC"].append(v)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is True

    def test_default_spike_multiplier_triggers(self):
        d = _make_detector(current_score=self.CURRENT, spike_multiplier=3.0)
        for v in self.BURSTY:
            d.centrality_history["ACC"].append(v)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is True

    def test_high_spike_multiplier_harder_to_trigger(self):
        d = _make_detector(current_score=self.CURRENT, spike_multiplier=5.0)
        for v in self.BURSTY:
            d.centrality_history["ACC"].append(v)
        risk, flagged = d.analyze_account("ACC")
        assert flagged is False


class TestAccountIsolation:
    """Baselines are kept per account."""

    def test_independent_histories(self):
        d = _make_detector(current_score=0.31)
        for _ in range(9):
            d.centrality_history["ACC_A"].append(0.1)
        for _ in range(9):
            d.centrality_history["ACC_B"].append(0.9)
        # ACC_A spikes relative to its own baseline...
        _, flagged_a = d.analyze_account("ACC_A")
        assert flagged_a is True
        # ...while ACC_B stays flat relative to its baseline.
        _, flagged_b = d.analyze_account("ACC_B")
        assert flagged_b is False
