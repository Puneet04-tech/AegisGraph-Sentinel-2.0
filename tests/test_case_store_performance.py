"""Tests for CaseStore indexing, counters, and bounded growth.

Covers the bottlenecks fixed in issue #2705: ``list_cases()`` copied and
fully sorted every stored case to return one page, ``get_dashboard_stats()``
re-scanned all cases on every poll, the audit map grew without bound while the
cases it was keyed by were LRU-evicted, and syslog emission ran inline while
the store lock was held.

The most important tests here are the ordering-equivalence ones: the fast path
must return byte-identical results to the original filter-sort-slice, including
for cases sharing a ``created_at`` second.
"""

import threading
import time

import pytest

from src.case_management.models import CasePriority, CaseStatus
from src.case_management.store import CaseStore


def _reference_list_cases(store, status=None, priority=None, assigned_analyst=None,
                          page=1, page_size=20):
    """Brute-force oracle: filter, order newest-first, slice.

    Mirrors the original filter-sort-slice, with one deliberate difference.
    ``created_at`` has one-second resolution, so cases created in the same
    second are tied. The original relied on Python's stable sort, which left a
    tie group in *ascending* insertion order — a burst of cases created in one
    second came back oldest-first. This oracle orders ties newest-first, which
    is what the endpoint claims to return and what the store now produces. See
    ``TestOrderingEquivalence::test_tie_order_is_newest_first`` for the pinned
    difference.
    """
    all_cases = list(store._cases.values())
    if status:
        all_cases = [c for c in all_cases if c.status == status]
    if priority:
        all_cases = [c for c in all_cases if c.priority == priority]
    if assigned_analyst is not None:
        all_cases = [c for c in all_cases if c.assigned_analyst == assigned_analyst]
    all_cases.reverse()
    all_cases.sort(key=lambda c: c.created_at, reverse=True)
    total = len(all_cases)
    start = (page - 1) * page_size
    return all_cases[start:start + page_size], total


def _legacy_list_cases(store, page=1, page_size=20):
    """The exact original implementation, for the tie-order comparison."""
    all_cases = list(store._cases.values())
    all_cases.sort(key=lambda c: c.created_at, reverse=True)
    start = (page - 1) * page_size
    return all_cases[start:start + page_size], len(all_cases)


def _seed(store, count, analyst_cycle=("ana_a", "ana_b", None)):
    created = []
    priorities = list(CasePriority)
    for i in range(count):
        case = store.create_case(
            transaction_id=f"TXN{i:06d}",
            risk_score=(i % 100) / 100.0,
            decision="REVIEW",
            analyst_id="seeder",
            priority=priorities[i % len(priorities)],
        )
        analyst = analyst_cycle[i % len(analyst_cycle)]
        if analyst is not None:
            store.assign_analyst(case.case_id, analyst, "seeder")
        created.append(case)
    return created


@pytest.fixture
def store():
    return CaseStore()


class TestOrderingEquivalence:
    """The fast path must not change what callers see."""

    def test_unfiltered_page_matches_reference(self, store):
        _seed(store, 200)
        for page in (1, 2, 5, 10):
            fast, fast_total = store.list_cases(page=page, page_size=20)
            slow, slow_total = _reference_list_cases(store, page=page, page_size=20)
            assert [c.case_id for c in fast] == [c.case_id for c in slow]
            assert fast_total == slow_total

    def test_tie_order_is_newest_first(self, store):
        """Pins the one deliberate behaviour change in this PR.

        Cases sharing a ``created_at`` second used to come back oldest-first,
        because the stable descending sort left the tie group in insertion
        order. They now come back newest-first, matching what the endpoint
        claims to return.
        """
        created = _seed(store, 50)
        timestamps = {c.created_at for c in store._cases.values()}
        assert len(timestamps) < 50, "expected tied created_at values in this seed"

        page, _ = store.list_cases(page=1, page_size=50)
        legacy, _ = _legacy_list_cases(store, page=1, page_size=50)

        # Newest-first: the most recently created case leads.
        assert page[0].case_id == created[-1].case_id
        # The legacy order led with the oldest of the tie group instead.
        assert legacy[0].case_id != page[0].case_id
        # Same set of cases either way — only the order within a tie differs.
        assert {c.case_id for c in page} == {c.case_id for c in legacy}

    def test_ordering_across_different_seconds_is_unchanged(self, store):
        """Cases from different seconds must still come back newest-first."""
        first = store.create_case("TXN_OLD", 0.5, "REVIEW", "ana")
        time.sleep(1.1)
        second = store.create_case("TXN_NEW", 0.5, "REVIEW", "ana")

        assert first.created_at != second.created_at
        page, _ = store.list_cases(page=1, page_size=10)
        assert [c.case_id for c in page] == [second.case_id, first.case_id]

    @pytest.mark.parametrize("status", list(CaseStatus))
    def test_status_filter_matches_reference(self, store, status):
        _seed(store, 120)
        fast, fast_total = store.list_cases(status=status, page_size=50)
        slow, slow_total = _reference_list_cases(store, status=status, page_size=50)
        assert [c.case_id for c in fast] == [c.case_id for c in slow]
        assert fast_total == slow_total

    @pytest.mark.parametrize("priority", list(CasePriority))
    def test_priority_filter_matches_reference(self, store, priority):
        _seed(store, 120)
        fast, fast_total = store.list_cases(priority=priority, page_size=50)
        slow, slow_total = _reference_list_cases(store, priority=priority, page_size=50)
        assert [c.case_id for c in fast] == [c.case_id for c in slow]
        assert fast_total == slow_total

    @pytest.mark.parametrize("analyst", ["ana_a", "ana_b", "nobody"])
    def test_analyst_filter_matches_reference(self, store, analyst):
        _seed(store, 120)
        fast, fast_total = store.list_cases(assigned_analyst=analyst, page_size=50)
        slow, slow_total = _reference_list_cases(
            store, assigned_analyst=analyst, page_size=50
        )
        assert [c.case_id for c in fast] == [c.case_id for c in slow]
        assert fast_total == slow_total

    def test_combined_filters_match_reference(self, store):
        _seed(store, 200)
        fast, fast_total = store.list_cases(
            status=CaseStatus.IN_PROGRESS,
            priority=CasePriority.HIGH,
            assigned_analyst="ana_a",
            page_size=50,
        )
        slow, slow_total = _reference_list_cases(
            store,
            status=CaseStatus.IN_PROGRESS,
            priority=CasePriority.HIGH,
            assigned_analyst="ana_a",
            page_size=50,
        )
        assert [c.case_id for c in fast] == [c.case_id for c in slow]
        assert fast_total == slow_total

    def test_ordering_survives_get_case_calls(self, store):
        """_LRUDict.__getitem__ reorders; the read paths must not trigger it."""
        cases = _seed(store, 50)
        for case in cases[:25]:
            store.get_case(case.case_id)

        fast, _ = store.list_cases(page_size=50)
        slow, _ = _reference_list_cases(store, page_size=50)
        assert [c.case_id for c in fast] == [c.case_id for c in slow]

    def test_empty_store(self, store):
        assert store.list_cases() == ([], 0)

    def test_page_beyond_the_end_is_empty(self, store):
        _seed(store, 10)
        page, total = store.list_cases(page=99, page_size=20)
        assert page == []
        assert total == 10

    def test_filter_matching_nothing(self, store):
        _seed(store, 20, analyst_cycle=("ana_a",))
        page, total = store.list_cases(assigned_analyst="ghost")
        assert page == []
        assert total == 0

    def test_last_partial_page(self, store):
        _seed(store, 25)
        page, total = store.list_cases(page=2, page_size=20)
        assert len(page) == 5
        assert total == 25


class TestWorkIsBounded:
    def test_page_one_does_not_touch_every_case(self, store):
        """The original walked all N records to return 20."""
        _seed(store, 2_000)
        touched = []

        original = store._iter_newest_first

        def counting_iter(candidate_ids):
            for case in original(candidate_ids):
                touched.append(case.case_id)
                yield case

        store._iter_newest_first = counting_iter
        store.list_cases(page=1, page_size=20)

        # Generator is consumed lazily via islice, so only the page is walked.
        assert len(touched) <= 25, f"walked {len(touched)} cases to return 20"

    def test_total_is_computed_without_scanning(self, store):
        _seed(store, 500)
        _, total = store.list_cases(status=CaseStatus.IN_PROGRESS, page_size=1)
        expected = len(store._by_status[CaseStatus.IN_PROGRESS])
        assert total == expected

    def test_listing_scales_sublinearly(self, store):
        """Page-one latency must not grow with total case count."""
        _seed(store, 500)
        start = time.perf_counter()
        for _ in range(50):
            store.list_cases(page=1, page_size=20)
        small = time.perf_counter() - start

        _seed(store, 4_500)
        start = time.perf_counter()
        for _ in range(50):
            store.list_cases(page=1, page_size=20)
        large = time.perf_counter() - start

        # 10x the data. The old implementation was linear, so this would be
        # ~10x slower; generous bound to stay stable on a loaded CI machine.
        assert large < small * 4, f"small={small:.4f}s large={large:.4f}s"


class TestIndexConsistency:
    def test_status_index_follows_transitions(self, store):
        case = _seed(store, 1, analyst_cycle=(None,))[0]
        assert case.case_id in store._by_status[CaseStatus.OPEN]

        store.update_status(case.case_id, CaseStatus.IN_PROGRESS, "ana")
        assert case.case_id not in store._by_status[CaseStatus.OPEN]
        assert case.case_id in store._by_status[CaseStatus.IN_PROGRESS]

    def test_priority_index_follows_updates(self, store):
        case = _seed(store, 1, analyst_cycle=(None,))[0]
        old = case.priority
        store.update_priority(case.case_id, CasePriority.CRITICAL, "ana")
        assert case.case_id in store._by_priority[CasePriority.CRITICAL]
        if old != CasePriority.CRITICAL:
            assert case.case_id not in store._by_priority[old]

    def test_analyst_index_follows_assignment(self, store):
        case = _seed(store, 1, analyst_cycle=(None,))[0]
        store.assign_analyst(case.case_id, "ana_x", "ana_x")
        assert case.case_id in store._by_analyst["ana_x"]

        store.assign_analyst(case.case_id, "ana_y", "ana_y")
        assert case.case_id in store._by_analyst["ana_y"]
        assert "ana_x" not in store._by_analyst

    def test_assignment_moves_open_case_to_in_progress_in_the_index(self, store):
        case = _seed(store, 1, analyst_cycle=(None,))[0]
        store.assign_analyst(case.case_id, "ana", "ana")
        assert case.case_id in store._by_status[CaseStatus.IN_PROGRESS]
        assert case.case_id not in store._by_status[CaseStatus.OPEN]

    def test_indexes_stay_consistent_under_random_mutation(self, store):
        import random

        rng = random.Random(1234)
        cases = _seed(store, 300)
        for _ in range(400):
            case = rng.choice(cases)
            action = rng.choice(("priority", "analyst"))
            if action == "priority":
                store.update_priority(
                    case.case_id, rng.choice(list(CasePriority)), "ana"
                )
            else:
                store.assign_analyst(case.case_id, f"ana_{rng.randint(0, 5)}", "ana")

        for status in CaseStatus:
            expected = {
                cid for cid, c in store._cases.items() if c.status == status
            }
            assert store._by_status[status] == expected
        for priority in CasePriority:
            expected = {
                cid for cid, c in store._cases.items() if c.priority == priority
            }
            assert store._by_priority[priority] == expected

    def test_concurrent_writers_leave_indexes_consistent(self, store):
        cases = _seed(store, 100)
        barrier = threading.Barrier(8)

        def mutate(offset):
            barrier.wait()
            for i, case in enumerate(cases):
                if i % 8 == offset:
                    store.update_priority(case.case_id, CasePriority.HIGH, "ana")

        threads = [threading.Thread(target=mutate, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        expected = {
            cid for cid, c in store._cases.items() if c.priority == CasePriority.HIGH
        }
        assert store._by_priority[CasePriority.HIGH] == expected


class TestDashboardCounters:
    def test_counts_match_a_full_recount(self, store):
        _seed(store, 250)
        stats = store.get_dashboard_stats()
        for status in CaseStatus:
            expected = sum(1 for c in store._cases.values() if c.status == status)
            assert stats["by_status"][status.value] == expected
        for priority in CasePriority:
            expected = sum(1 for c in store._cases.values() if c.priority == priority)
            assert stats["by_priority"][priority.value] == expected

    def test_counts_track_mutations(self, store):
        case = _seed(store, 1, analyst_cycle=(None,))[0]
        before = store.get_dashboard_stats()
        store.update_status(case.case_id, CaseStatus.ESCALATED, "ana")
        after = store.get_dashboard_stats()

        assert after["escalated_cases"] == before["escalated_cases"] + 1
        assert after["open_cases"] == before["open_cases"] - 1

    def test_totals_are_consistent(self, store):
        _seed(store, 120)
        stats = store.get_dashboard_stats()
        assert sum(stats["by_status"].values()) == stats["total_cases"]
        assert sum(stats["by_priority"].values()) == stats["total_cases"]

    def test_empty_store_reports_zeroes(self, store):
        stats = store.get_dashboard_stats()
        assert stats["total_cases"] == 0
        assert all(v == 0 for v in stats["by_status"].values())

    def test_response_shape_is_unchanged(self, store):
        _seed(store, 5)
        stats = store.get_dashboard_stats()
        assert set(stats) == {
            "total_cases",
            "by_status",
            "by_priority",
            "open_cases",
            "in_progress_cases",
            "escalated_cases",
        }


class TestBoundedGrowth:
    def _small_store(self, maxsize=10):
        store = CaseStore()
        store._cases.maxsize = maxsize
        return store

    def test_eviction_reclaims_audit_entries(self):
        """The audit map used to outlive the cases it was keyed by."""
        store = self._small_store(maxsize=10)
        first = store.create_case("TXN1", 0.5, "REVIEW", "ana")
        for i in range(20):
            store.create_case(f"TXN_FILL_{i}", 0.5, "REVIEW", "ana")

        assert first.case_id not in store._cases
        assert first.case_id not in store._audit
        assert len(store._audit) <= 10

    def test_eviction_reclaims_comments_and_evidence(self):
        from src.case_management.models import EvidenceType

        store = self._small_store(maxsize=5)
        first = store.create_case("TXN1", 0.5, "REVIEW", "ana")
        store.add_comment(first.case_id, "ana", "a note")
        store.add_evidence(first.case_id, "ana", EvidenceType.NOTE, "some evidence")
        assert len(store._comments) == 1
        assert len(store._evidence) == 1

        for i in range(10):
            store.create_case(f"TXN_FILL_{i}", 0.5, "REVIEW", "ana")

        assert first.case_id not in store._cases
        assert len(store._comments) == 0
        assert len(store._evidence) == 0

    def test_eviction_reclaims_index_entries(self):
        store = self._small_store(maxsize=5)
        first = store.create_case("TXN1", 0.5, "REVIEW", "ana")
        for i in range(10):
            store.create_case(f"TXN_FILL_{i}", 0.5, "REVIEW", "ana")

        for bucket in store._by_status.values():
            assert first.case_id not in bucket
        for bucket in store._by_priority.values():
            assert first.case_id not in bucket

    def test_counters_stay_correct_across_eviction(self):
        store = self._small_store(maxsize=10)
        for i in range(40):
            store.create_case(f"TXN{i}", 0.5, "REVIEW", "ana")

        stats = store.get_dashboard_stats()
        assert stats["total_cases"] == 10
        assert sum(stats["by_status"].values()) == 10
        assert sum(stats["by_priority"].values()) == 10

    def test_per_case_audit_is_capped(self, store):
        case = store.create_case("TXN1", 0.5, "REVIEW", "ana")
        store.MAX_AUDIT_EVENTS_PER_CASE = 5
        for i in range(20):
            store._append_audit(case.case_id, "ana", f"ACTION_{i}")

        timeline = store.get_timeline(case.case_id)
        assert len(timeline) == 5
        # Oldest dropped first, so the most recent survive.
        assert timeline[-1].action == "ACTION_19"


class _RecordingSyslog:
    """Syslog client that records whether the store lock was held on send."""

    def __init__(self, store):
        self.store = store
        self.calls = []
        self.lock_held_during_send = []

    def log_event(self, **payload):
        acquired = self.store._lock.acquire(blocking=False)
        if acquired:
            self.store._lock.release()
        # If we could not acquire it, some other thread held it during our send.
        self.lock_held_during_send.append(not acquired)
        self.calls.append(payload)
        return True


class TestSyslogOffTheCriticalPath:
    def test_emission_does_not_happen_inline(self, store):
        """The send used to run while self._lock was held, on the event loop."""
        recorder = _RecordingSyslog(store)
        store.syslog_client = recorder

        store.create_case("TXN1", 0.5, "REVIEW", "ana")
        # Nothing is required to have been sent yet — it is queued, not inline.
        store.flush_syslog(timeout=5.0)

        assert recorder.calls, "audit event never reached the syslog client"
        assert not any(recorder.lock_held_during_send)

    def test_payload_is_unchanged(self, store):
        recorder = _RecordingSyslog(store)
        store.syslog_client = recorder
        case = store.create_case("TXN1", 0.5, "REVIEW", "ana")
        store.flush_syslog(timeout=5.0)

        payload = recorder.calls[0]
        assert payload["msg_id"] == "CASE_CREATED"
        assert payload["metadata"]["case_id"] == case.case_id
        assert payload["metadata"]["analyst_id"] == "ana"

    def test_escalation_severity_is_preserved(self, store):
        recorder = _RecordingSyslog(store)
        store.syslog_client = recorder
        case = store.create_case("TXN1", 0.5, "REVIEW", "ana")
        store.update_status(case.case_id, CaseStatus.ESCALATED, "ana")
        store.flush_syslog(timeout=5.0)

        escalation = [c for c in recorder.calls if c["msg_id"] == "STATUS_CHANGED"]
        assert escalation and escalation[0]["severity"] == 4

    def test_a_failing_client_does_not_break_case_creation(self, store):
        class Exploding:
            def log_event(self, **payload):
                raise ConnectionError("syslog unreachable")

        store.syslog_client = Exploding()
        case = store.create_case("TXN1", 0.5, "REVIEW", "ana")
        store.flush_syslog(timeout=5.0)
        assert store.get_case(case.case_id) is case

    def test_full_queue_drops_instead_of_blocking(self, store):
        import queue as queue_mod

        store._syslog_queue = queue_mod.Queue(maxsize=2)
        for i in range(20):
            store._enqueue_syslog({"msg_id": f"E{i}", "message": "m", "severity": 6})

        assert store._syslog_dropped > 0
        assert store._syslog_queue.qsize() <= 2

    def test_a_slow_client_does_not_stall_writes(self, store):
        class Slow:
            def log_event(self, **payload):
                time.sleep(0.2)
                return True

        store.syslog_client = Slow()
        start = time.perf_counter()
        for i in range(10):
            store.create_case(f"TXN{i}", 0.5, "REVIEW", "ana")
        elapsed = time.perf_counter() - start

        # Inline emission would have cost at least 10 * 0.2s.
        assert elapsed < 1.0, f"writes blocked on syslog for {elapsed:.2f}s"


class TestExistingBehaviourPreserved:
    def test_create_and_fetch(self, store):
        case = store.create_case("TXN1", 0.9, "BLOCK", "ana")
        assert store.get_case(case.case_id) is case

    def test_timeline_records_creation(self, store):
        case = store.create_case("TXN1", 0.9, "BLOCK", "ana")
        assert [e.action for e in store.get_timeline(case.case_id)] == ["CASE_CREATED"]

    def test_claim_case_rejects_a_taken_case(self, store):
        case = store.create_case("TXN1", 0.9, "BLOCK", "ana")
        store.claim_case(case.case_id, "ana_a")
        with pytest.raises(ValueError, match="already assigned"):
            store.claim_case(case.case_id, "ana_b")

    def test_unknown_case_raises(self, store):
        with pytest.raises(KeyError):
            store.get_timeline("CASE_DOES_NOT_EXIST")

    def test_invalid_transition_still_rejected(self, store):
        case = store.create_case("TXN1", 0.9, "BLOCK", "ana")
        with pytest.raises(ValueError):
            store.update_status(case.case_id, CaseStatus.RESOLVED, "ana")
