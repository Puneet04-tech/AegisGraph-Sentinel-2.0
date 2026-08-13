"""Tests that regulatory fabric handler failures surface.

All three notification paths ended in ``except Exception: pass``, and the
drift detector invoked its handlers while holding a non-reentrant lock.
"""

import threading

import pytest

from src.regulatory_fabric.change_tracker import RegulatoryChangeTracker
from src.regulatory_fabric.drift_detector import ComplianceDriftDetector
from src.regulatory_fabric.intelligence_engine import (
    IntelligenceAlert,
    RegulationIntelligenceEngine,
)


class FakeStore:
    """Minimal store surface used by these three modules."""

    def __init__(self):
        self.controls = {}
        self.policies = {}
        self.control_mappings = {}
        self.updates = {}

    def add_regulatory_update(self, update):
        self.updates[update["update_id"]] = update
        return update


@pytest.fixture
def store():
    return FakeStore()


def boom(*args, **kwargs):
    raise RuntimeError("handler exploded")


class TestChangeTrackerHandlers:
    """Change alerts report handler failures."""

    def _track(self, tracker):
        return tracker.track_update({
            "update_id": "u1",
            "regulation_id": "GDPR",
            "title": "Update",
            "summary": "Something changed",
        })

    def test_failure_is_logged(self, store, caplog):
        tracker = RegulatoryChangeTracker(store)
        tracker.register_change_handler(boom)

        with caplog.at_level("WARNING"):
            self._track(tracker)

        assert "handler" in caplog.text.lower()

    def test_one_failure_does_not_starve_the_others(self, store):
        tracker = RegulatoryChangeTracker(store)
        received = []
        tracker.register_change_handler(boom)
        tracker.register_change_handler(received.append)

        self._track(tracker)

        assert len(received) == 1

    def test_tracking_still_succeeds(self, store):
        tracker = RegulatoryChangeTracker(store)
        tracker.register_change_handler(boom)

        assert self._track(tracker) == "u1"


class TestIntelligenceSubscribers:
    """Intelligence alerts report subscriber failures."""

    def _alert(self):
        return IntelligenceAlert(
            alert_id="a1",
            alert_type="REGULATORY_UPDATE",
            severity="HIGH",
            title="Alert",
            description="",
            regulation_id="GDPR",
            source="s1",
        )

    def test_failure_is_logged(self, store, caplog):
        engine = RegulationIntelligenceEngine(store)
        engine.subscribe(boom)

        with caplog.at_level("WARNING"):
            engine._notify_subscribers(self._alert())

        assert "subscriber" in caplog.text.lower()

    def test_one_failure_does_not_starve_the_others(self, store):
        engine = RegulationIntelligenceEngine(store)
        received = []
        engine.subscribe(boom)
        engine.subscribe(received.append)

        engine._notify_subscribers(self._alert())

        assert len(received) == 1

    def test_subscribing_from_a_handler_does_not_deadlock(self, store):
        engine = RegulationIntelligenceEngine(store)

        def resubscribe(alert):
            engine.subscribe(lambda _: None)

        engine.subscribe(resubscribe)

        finished = threading.Event()

        def run():
            engine._notify_subscribers(self._alert())
            finished.set()

        threading.Thread(target=run, daemon=True).start()

        assert finished.wait(timeout=5), "notification deadlocked"


class TestDriftDetectorHandlers:
    """Drift handlers run outside the lock and report failures."""

    def _detector_with_drift(self, store):
        store.controls = {"c1": {"status": "COMPLIANT"}}
        detector = ComplianceDriftDetector(store)
        detector.capture_baseline()
        # Removing the control produces a CONTROL_REMOVED drift event.
        store.controls = {}
        return detector

    def test_drift_is_detected(self, store):
        detector = self._detector_with_drift(store)

        assert detector.detect_drift()

    def test_failure_is_logged(self, store, caplog):
        detector = self._detector_with_drift(store)
        detector.register_drift_handler(boom)

        with caplog.at_level("WARNING"):
            detector.detect_drift()

        assert "handler" in caplog.text.lower()

    def test_one_failure_does_not_starve_the_others(self, store):
        detector = self._detector_with_drift(store)
        received = []
        detector.register_drift_handler(boom)
        detector.register_drift_handler(received.append)

        detector.detect_drift()

        assert len(received) == 1

    def test_handler_touching_the_detector_does_not_deadlock(self, store):
        # Handlers were invoked while self._lock was held. Since it is a
        # plain Lock, a handler that re-entered the detector deadlocked the
        # process permanently.
        detector = self._detector_with_drift(store)

        def reentrant(event):
            detector.register_drift_handler(lambda _: None)

        detector.register_drift_handler(reentrant)

        finished = threading.Event()

        def run():
            detector.detect_drift()
            finished.set()

        threading.Thread(target=run, daemon=True).start()

        assert finished.wait(timeout=5), "drift notification deadlocked"

    def test_events_are_still_recorded_when_a_handler_fails(self, store):
        detector = self._detector_with_drift(store)
        detector.register_drift_handler(boom)

        events = detector.detect_drift()

        assert events
        assert detector._drift_events
