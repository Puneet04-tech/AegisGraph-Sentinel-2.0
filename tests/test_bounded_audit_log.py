"""Tests for the shared bounded audit log and its monotonic id source."""

import threading

import pytest

from src.audit.bounded_log import (
    DEFAULT_AUDIT_CAPACITY,
    BoundedAuditLog,
    default_capacity,
    next_event_id,
    reset_event_ids,
)


@pytest.fixture(autouse=True)
def _reset_ids():
    reset_event_ids()
    yield
    reset_event_ids()


class TestCapacity:
    def test_retains_up_to_capacity(self):
        log = BoundedAuditLog(capacity=5)
        for i in range(5):
            log.append(i)
        assert len(log) == 5
        assert log.all() == [0, 1, 2, 3, 4]

    def test_evicts_oldest_first(self):
        log = BoundedAuditLog(capacity=3)
        for i in range(6):
            log.append(i)
        assert log.all() == [3, 4, 5]

    def test_memory_stays_constant_under_sustained_appends(self):
        log = BoundedAuditLog(capacity=100)
        for i in range(100_000):
            log.append(i)
        assert len(log) == 100
        assert log.all()[-1] == 99_999

    def test_dropped_counter_is_accurate(self):
        log = BoundedAuditLog(capacity=3)
        for i in range(10):
            log.append(i)
        assert log.dropped == 7

    def test_nothing_dropped_below_capacity(self):
        log = BoundedAuditLog(capacity=10)
        log.extend(range(4))
        assert log.dropped == 0

    def test_non_positive_capacity_falls_back_to_the_default(self):
        # A zero bound would silently discard everything.
        assert BoundedAuditLog(capacity=0).capacity == DEFAULT_AUDIT_CAPACITY
        assert BoundedAuditLog(capacity=-5).capacity == DEFAULT_AUDIT_CAPACITY

    def test_default_capacity_is_used_when_unspecified(self):
        assert BoundedAuditLog().capacity == default_capacity()


class TestConfiguredCapacity:
    def test_environment_override_is_honoured(self, monkeypatch):
        monkeypatch.setenv("AEGIS_AUDIT_LOG_CAPACITY", "42")
        assert default_capacity() == 42
        assert BoundedAuditLog().capacity == 42

    def test_unparseable_override_falls_back(self, monkeypatch):
        # An unparseable env var must not stop the process from starting.
        monkeypatch.setenv("AEGIS_AUDIT_LOG_CAPACITY", "not-a-number")
        assert default_capacity() == DEFAULT_AUDIT_CAPACITY

    def test_non_positive_override_falls_back(self, monkeypatch):
        monkeypatch.setenv("AEGIS_AUDIT_LOG_CAPACITY", "0")
        assert default_capacity() == DEFAULT_AUDIT_CAPACITY
        monkeypatch.setenv("AEGIS_AUDIT_LOG_CAPACITY", "-1")
        assert default_capacity() == DEFAULT_AUDIT_CAPACITY

    def test_unset_uses_the_default(self, monkeypatch):
        monkeypatch.delenv("AEGIS_AUDIT_LOG_CAPACITY", raising=False)
        assert default_capacity() == DEFAULT_AUDIT_CAPACITY


class TestTailSemantics:
    """tail(limit) must match the `self._audit_log[-limit:]` it replaces."""

    def test_returns_the_most_recent_entries_oldest_first(self):
        log = BoundedAuditLog(capacity=100)
        log.extend(range(10))
        assert log.tail(3) == [7, 8, 9]

    def test_limit_larger_than_retained_returns_everything(self):
        log = BoundedAuditLog(capacity=100)
        log.extend(range(4))
        assert log.tail(50) == [0, 1, 2, 3]

    def test_limit_equal_to_size(self):
        log = BoundedAuditLog(capacity=100)
        log.extend(range(4))
        assert log.tail(4) == [0, 1, 2, 3]

    def test_non_positive_limit_returns_empty(self):
        log = BoundedAuditLog(capacity=10)
        log.extend(range(5))
        assert log.tail(0) == []
        assert log.tail(-3) == []

    def test_tail_on_an_empty_log(self):
        assert BoundedAuditLog(capacity=10).tail(5) == []

    def test_tail_returns_a_snapshot_not_a_live_view(self):
        log = BoundedAuditLog(capacity=10)
        log.extend(range(3))
        snapshot = log.tail(3)
        log.append(99)
        assert snapshot == [0, 1, 2]


class TestSequenceProtocol:
    def test_len_and_bool(self):
        log = BoundedAuditLog(capacity=5)
        assert len(log) == 0
        assert not log
        log.append("x")
        assert len(log) == 1
        assert log

    def test_iteration_is_oldest_first(self):
        log = BoundedAuditLog(capacity=5)
        log.extend(range(3))
        assert list(log) == [0, 1, 2]

    def test_reversed_is_newest_first(self):
        log = BoundedAuditLog(capacity=5)
        log.extend(range(3))
        assert list(reversed(log)) == [2, 1, 0]

    def test_indexing_and_slicing(self):
        log = BoundedAuditLog(capacity=10)
        log.extend(range(5))
        assert log[0] == 0
        assert log[-1] == 4
        assert log[-2:] == [3, 4]

    def test_clear_empties_and_resets_the_counter(self):
        log = BoundedAuditLog(capacity=2)
        log.extend(range(10))
        assert log.dropped > 0

        log.clear()
        assert len(log) == 0
        assert log.dropped == 0
        assert log.all() == []

    def test_stats_reports_retention(self):
        log = BoundedAuditLog(capacity=3)
        log.extend(range(5))
        assert log.stats() == {"retained": 3, "capacity": 3, "dropped": 2}


class TestEventIds:
    def test_ids_are_unique_and_monotonic(self):
        ids = [next_event_id() for _ in range(100)]
        assert len(set(ids)) == 100
        assert ids[0] == "audit-1"
        assert ids[-1] == "audit-100"

    def test_ids_do_not_repeat_after_a_log_is_cleared(self):
        """The exact defect in `f"audit-{len(log) + 1}"`.

        Length-derived ids restart from 1 after a clear, so new events reuse
        ids that already identify different historical events.
        """
        log = BoundedAuditLog(capacity=10)
        for _ in range(5):
            log.append(next_event_id())
        before = set(log.all())

        log.clear()
        after = {next_event_id() for _ in range(5)}

        assert before.isdisjoint(after)

    def test_ids_do_not_repeat_after_eviction(self):
        log = BoundedAuditLog(capacity=3)
        seen = set()
        for _ in range(50):
            event_id = next_event_id()
            assert event_id not in seen
            seen.add(event_id)
            log.append(event_id)

    def test_ids_are_unique_across_separate_log_instances(self):
        first = next_event_id()
        second = next_event_id()
        assert first != second

    def test_prefix_is_honoured(self):
        assert next_event_id("record").startswith("record-")


class TestConcurrency:
    def test_concurrent_appends_lose_nothing(self):
        log = BoundedAuditLog(capacity=10_000)

        def writer(offset: int) -> None:
            for i in range(500):
                log.append(f"{offset}_{i}")

        threads = [threading.Thread(target=writer, args=(o,)) for o in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(log) == 4000
        assert len(set(log.all())) == 4000

    def test_concurrent_id_generation_never_collides(self):
        collected = []
        lock = threading.Lock()

        def generator() -> None:
            local = [next_event_id() for _ in range(300)]
            with lock:
                collected.extend(local)

        threads = [threading.Thread(target=generator) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(collected) == 2400
        assert len(set(collected)) == 2400

    def test_reads_during_writes_stay_consistent(self):
        log = BoundedAuditLog(capacity=1000)
        errors = []

        def writer() -> None:
            try:
                for i in range(400):
                    log.append(i)
            except Exception as exc:  # pragma: no cover - surfaced by assertion
                errors.append(exc)

        def reader() -> None:
            try:
                for _ in range(400):
                    log.tail(50)
                    list(log)
                    len(log)
            except Exception as exc:  # pragma: no cover - surfaced by assertion
                errors.append(exc)

        threads = [threading.Thread(target=writer) for _ in range(3)]
        threads += [threading.Thread(target=reader) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
