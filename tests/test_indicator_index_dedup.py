"""
Tests for threat indicator index deduplication in GlobalIntelligenceStore.

Regression tests for the duplicate indicator index entries: re-storing an
indicator (an update) used to append the same indicator_id to the type/threat
index lists, so get_indicators_by_type returned duplicate results and the
[:limit] slice could starve distinct indicators.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.global_intelligence import (
    GlobalIntelligenceStore,
    ThreatIndicator,
    ThreatLevel,
    IntelligenceSource,
)

NOW = datetime.now(timezone.utc)


def make_indicator(
    indicator_id,
    indicator_type="ip",
    threat_type="malware",
    value=None,
    confidence=0.9,
    expiration_days=7,
    threat_level=ThreatLevel.HIGH,
):
    """Build a ThreatIndicator with deterministic defaults."""
    return ThreatIndicator(
        indicator_id=indicator_id,
        indicator_type=indicator_type,
        value=value or indicator_id,
        source=IntelligenceSource.INTERNAL,
        threat_type=threat_type,
        threat_level=threat_level,
        confidence=confidence,
        first_seen=NOW,
        last_seen=NOW,
        expiration=NOW + timedelta(days=expiration_days)
        if expiration_days is not None
        else None,
        partner_id="p1",
        tags=["test"],
    )


class TestIndicatorIndexDedup:
    """Indicator index must never return the same indicator twice."""

    @pytest.fixture(autouse=True)
    def fresh_store(self):
        self.store = GlobalIntelligenceStore()

    def test_restore_same_indicator_returns_single_result(self):
        indicator = make_indicator("ind-1")
        self.store.store_indicator(indicator)
        self.store.store_indicator(indicator)

        results = self.store.get_indicators_by_type("ip")

        assert len(results) == 1
        assert results[0].indicator_id == "ind-1"

    def test_restore_does_not_duplicate_threat_type_index(self):
        indicator = make_indicator("ind-1", threat_type="phishing")
        self.store.store_indicator(indicator)
        self.store.store_indicator(indicator)

        results = self.store.get_indicators_by_type("phishing")

        assert [r.indicator_id for r in results] == ["ind-1"]

    def test_limit_not_starved_by_duplicates(self):
        for iid in ["a", "b", "b", "c"]:
            self.store.store_indicator(make_indicator(iid))

        results = self.store.get_indicators_by_type("ip", limit=3)

        assert len(results) == 3
        assert sorted(r.indicator_id for r in results) == ["a", "b", "c"]

    def test_insertion_order_preserved_across_restores(self):
        for iid in ["a", "b", "c"]:
            self.store.store_indicator(make_indicator(iid))
        self.store.store_indicator(make_indicator("b", confidence=0.99))

        results = self.store.get_indicators_by_type("ip")

        assert [r.indicator_id for r in results] == ["a", "b", "c"]
        assert results[1].confidence == 0.99

    def test_restore_updates_value_not_index_count(self):
        self.store.store_indicator(make_indicator("ind-1", value="1.2.3.4"))
        self.store.store_indicator(make_indicator("ind-1", value="5.6.7.8"))

        results = self.store.get_indicators_by_type("ip")

        assert len(results) == 1
        assert self.store.get_indicator("ind-1").value == "5.6.7.8"

    def test_many_restores_yield_single_entry(self):
        indicator = make_indicator("ind-1")
        for _ in range(100):
            self.store.store_indicator(indicator)

        assert len(self.store.get_indicators_by_type("ip")) == 1
        assert len(self.store.get_indicators_by_type("malware")) == 1

    def test_distinct_indicators_all_retained(self):
        for iid in ["a", "b", "c", "d", "e"]:
            self.store.store_indicator(make_indicator(iid))

        results = self.store.get_indicators_by_type("ip")

        assert sorted(r.indicator_id for r in results) == ["a", "b", "c", "d", "e"]

    def test_same_id_shared_across_types_indexed_in_both(self):
        indicator = make_indicator("ind-1", indicator_type="domain", threat_type="malware")
        self.store.store_indicator(indicator)
        self.store.store_indicator(indicator)

        assert [r.indicator_id for r in self.store.get_indicators_by_type("domain")] == ["ind-1"]
        assert [r.indicator_id for r in self.store.get_indicators_by_type("malware")] == ["ind-1"]
        assert len(self.store.get_indicators_by_type("domain")) == 1
        assert len(self.store.get_indicators_by_type("malware")) == 1

    def test_expired_indicators_still_filtered_from_index(self):
        self.store.store_indicator(make_indicator("ind-1", expiration_days=-1))
        self.store.store_indicator(make_indicator("ind-2", expiration_days=7))

        results = self.store.get_indicators_by_type("ip")

        assert [r.indicator_id for r in results] == ["ind-2"]

    def test_expired_duplicate_never_surfaces(self):
        expired = make_indicator("ind-1", expiration_days=-1)
        self.store.store_indicator(expired)
        self.store.store_indicator(expired)

        assert self.store.get_indicators_by_type("ip") == []

    def test_unknown_type_returns_empty(self):
        assert self.store.get_indicators_by_type("nonexistent") == []

    def test_active_indicator_query_unaffected_by_restores(self):
        self.store.store_indicator(make_indicator("a"))
        self.store.store_indicator(make_indicator("a"))
        self.store.store_indicator(make_indicator("b"))

        active = self.store.get_active_indicators()

        assert sorted(i.indicator_id for i in active) == ["a", "b"]

    def test_search_indicator_query_unaffected_by_restores(self):
        self.store.store_indicator(make_indicator("a", value="10.0.0.1"))
        self.store.store_indicator(make_indicator("a", value="10.0.0.1"))

        found = self.store.search_indicators("10.0.0.1")

        assert len(found) == 1
        assert found[0].indicator_id == "a"

    def test_get_indicator_returns_latest_on_restore(self):
        self.store.store_indicator(make_indicator("ind-1", confidence=0.5))
        self.store.store_indicator(make_indicator("ind-1", confidence=0.95))

        assert self.store.get_indicator("ind-1").confidence == 0.95
        assert len(self.store.get_indicators_by_type("ip")) == 1

    def test_lru_eviction_does_not_leak_stale_ids(self):
        small_store = GlobalIntelligenceStore(max_indicators=3)
        for iid in ["a", "b", "c", "d"]:
            small_store.store_indicator(make_indicator(iid))

        results = small_store.get_indicators_by_type("ip")

        assert len(results) <= 3
        assert all(r.indicator_id in {"a", "b", "c", "d"} for r in results)
        assert all(small_store.get_indicator(r.indicator_id) is not None for r in results)

    def test_evicted_and_restored_indicator_not_duplicated(self):
        small_store = GlobalIntelligenceStore(max_indicators=2)
        for iid in ["a", "b", "c"]:
            small_store.store_indicator(make_indicator(iid))
        small_store.store_indicator(make_indicator("a"))

        results = small_store.get_indicators_by_type("ip")

        assert len(results) == 2
        assert [r.indicator_id for r in results] == ["a", "c"]

    def test_type_and_threat_indexes_stay_consistent(self):
        self.store.store_indicator(make_indicator("a", indicator_type="ip", threat_type="malware"))
        self.store.store_indicator(make_indicator("a", indicator_type="ip", threat_type="malware"))
        self.store.store_indicator(make_indicator("b", indicator_type="domain", threat_type="malware"))

        assert sorted(r.indicator_id for r in self.store.get_indicators_by_type("malware")) == ["a", "b"]
        assert [r.indicator_id for r in self.store.get_indicators_by_type("ip")] == ["a"]
        assert [r.indicator_id for r in self.store.get_indicators_by_type("domain")] == ["b"]

    def test_stats_count_not_inflated_by_restores(self):
        self.store.store_indicator(make_indicator("a"))
        self.store.store_indicator(make_indicator("a"))
        self.store.store_indicator(make_indicator("b"))

        stats = self.store.get_stats()

        assert stats["total_indicators"] == 2
        assert stats["active_indicators"] == 2

    def test_threaded_restores_keep_index_single(self):
        import threading

        errors = []

        def worker():
            try:
                for _ in range(50):
                    self.store.store_indicator(make_indicator("shared"))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(self.store.get_indicators_by_type("ip")) == 1
        assert self.store.get_stats()["total_indicators"] == 1
