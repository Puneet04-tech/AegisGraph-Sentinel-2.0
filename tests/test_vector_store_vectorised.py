"""Tests for vectorised VectorStore similarity search.

`query()` used to loop over every stored embedding in Python, calling a helper
that recomputed each stored vector's norm on every call. These tests assert the
matrix-backed replacement returns results identical to that loop, and that the
row bookkeeping underneath it stays consistent through eviction and removal.
"""

import threading

import numpy as np
import pytest

from src.case_management.vector_store import SearchResult, VectorStore

DIM = 16


def unit(*components) -> np.ndarray:
    """Build a normalised vector from its leading components."""
    vector = np.zeros(DIM, dtype=np.float32)
    vector[: len(components)] = components
    return vector


def brute_force_query(store: VectorStore, embedding, k, threshold):
    """The implementation this PR replaces, kept as the reference oracle."""
    results = []
    for case_id, (stored, metadata) in store._embeddings.items():
        a_norm = np.linalg.norm(embedding)
        b_norm = np.linalg.norm(stored)
        if a_norm == 0 or b_norm == 0:
            sim = 0.0
        else:
            sim = float(np.clip(np.dot(embedding / a_norm, stored / b_norm), 0.0, 1.0))
        if sim >= threshold:
            results.append(SearchResult(case_id, sim, metadata.copy()))
    results.sort(key=lambda r: r.similarity_score, reverse=True)
    return results[:k]


@pytest.fixture
def store() -> VectorStore:
    return VectorStore(embedding_dim=DIM, maxsize=100, similarity_threshold=0.0)


class TestEquivalenceWithBruteForce:
    def test_matches_reference_on_randomised_stores(self, store):
        rng = np.random.default_rng(11)
        for i in range(60):
            store.add(f"c{i}", rng.standard_normal(DIM).astype(np.float32))

        for _ in range(15):
            query = rng.standard_normal(DIM).astype(np.float32)
            expected = brute_force_query(store, query, k=10, threshold=0.0)
            actual = store.query(query, k=10, threshold=0.0)

            assert [r.case_id for r in actual] == [r.case_id for r in expected]
            for got, want in zip(actual, expected):
                assert got.similarity_score == pytest.approx(want.similarity_score, abs=1e-5)

    def test_threshold_is_respected(self, store):
        store.add("same", unit(1.0))
        store.add("orthogonal", unit(0.0, 1.0))

        results = store.query(unit(1.0), k=10, threshold=0.5)
        assert [r.case_id for r in results] == ["same"]

    def test_identical_vector_scores_one(self, store):
        vector = unit(0.6, 0.8)
        store.add("c1", vector)
        assert store.query(vector, k=1, threshold=0.0)[0].similarity_score == pytest.approx(1.0)

    def test_opposite_vector_is_clamped_to_zero(self, store):
        store.add("c1", unit(1.0))
        results = store.query(unit(-1.0), k=1, threshold=0.0)
        assert results[0].similarity_score == pytest.approx(0.0)

    def test_results_are_ordered_by_descending_similarity(self, store):
        store.add("far", unit(0.0, 1.0))
        store.add("near", unit(0.9, 0.1))
        store.add("exact", unit(1.0))

        results = store.query(unit(1.0), k=3, threshold=0.0)
        scores = [r.similarity_score for r in results]
        assert scores == sorted(scores, reverse=True)
        assert results[0].case_id == "exact"

    def test_equal_scores_keep_insertion_order(self, store):
        for case_id in ("first", "second", "third"):
            store.add(case_id, unit(1.0))

        results = store.query(unit(1.0), k=3, threshold=0.0)
        assert [r.case_id for r in results] == ["first", "second", "third"]


class TestBatchQuery:
    def test_matches_single_queries(self, store):
        rng = np.random.default_rng(3)
        for i in range(25):
            store.add(f"c{i}", rng.standard_normal(DIM).astype(np.float32))

        queries = rng.standard_normal((5, DIM)).astype(np.float32)
        batched = store.query_batch(queries, k=4, threshold=0.0)

        for query, batch_result in zip(queries, batched):
            single = store.query(query, k=4, threshold=0.0)
            assert [r.case_id for r in batch_result] == [r.case_id for r in single]

    def test_empty_batch_returns_empty(self, store):
        store.add("c1", unit(1.0))
        assert store.query_batch(np.zeros((0, DIM), dtype=np.float32), k=3) == []

    def test_batch_against_empty_store(self, store):
        result = store.query_batch(np.ones((3, DIM), dtype=np.float32), k=3)
        assert result == [[], [], []]

    def test_wrong_batch_dimension_raises(self, store):
        with pytest.raises(ValueError, match="dimension mismatch"):
            store.query_batch(np.ones((2, DIM + 1), dtype=np.float32), k=3)


class TestRowBookkeeping:
    def test_eviction_frees_and_reuses_a_row(self):
        store = VectorStore(embedding_dim=DIM, maxsize=3, similarity_threshold=0.0)
        for i in range(3):
            store.add(f"c{i}", unit(1.0, i))

        store.add("c3", unit(1.0, 9))

        assert store.size() == 3
        assert "c0" not in store._row_of
        # The evicted row goes back on the free list rather than being stranded.
        assert store._free_rows == [0]

        # ...and the next insert reuses it instead of growing the matrix.
        store.add("c4", unit(1.0, 11))
        assert store._row_of["c4"] == 0
        # That insert evicted c1 in turn, so exactly one row is free again --
        # the free list stays at a steady state rather than growing.
        assert store._free_rows == [1]
        assert store._matrix.shape[0] == 4  # maxsize + 1 row of headroom

        # Rows stay unique across the whole eviction cycle.
        assert len(set(store._row_of.values())) == store.size()

    def test_evicted_case_is_not_returned_by_query(self):
        store = VectorStore(embedding_dim=DIM, maxsize=2, similarity_threshold=0.0)
        store.add("old", unit(1.0))
        store.add("mid", unit(0.0, 1.0))
        store.add("new", unit(0.0, 0.0, 1.0))

        found = {r.case_id for r in store.query(unit(1.0), k=10, threshold=0.0)}
        assert "old" not in found

    def test_remove_frees_the_row_and_hides_the_case(self, store):
        store.add("c1", unit(1.0))
        store.add("c2", unit(0.0, 1.0))

        assert store.remove("c1") is True
        assert "c1" not in store._row_of
        assert {r.case_id for r in store.query(unit(1.0), k=10, threshold=0.0)} == {"c2"}

    def test_removing_an_absent_case_reports_false(self, store):
        assert store.remove("ghost") is False

    def test_updating_an_existing_case_reuses_its_row(self, store):
        store.add("c1", unit(1.0))
        row = store._row_of["c1"]
        store.add("c1", unit(0.0, 1.0))

        assert store._row_of["c1"] == row
        assert store.size() == 1
        # The query reflects the new vector, not the replaced one.
        assert store.query(unit(0.0, 1.0), k=1, threshold=0.9)[0].case_id == "c1"

    def test_clear_resets_all_row_state(self, store):
        store.add("c1", unit(1.0))
        store.clear()

        assert store.size() == 0
        assert store._row_of == {}
        assert store._next_row == 0
        assert store.query(unit(1.0), k=1, threshold=0.0) == []

    def test_batch_add_allocates_distinct_rows(self, store):
        ids = [f"c{i}" for i in range(10)]
        store.add_batch(ids, np.eye(10, DIM, dtype=np.float32))

        assert len(set(store._row_of.values())) == 10
        assert store.size() == 10


class TestDegenerateInput:
    def test_zero_query_vector_returns_no_matches(self, store):
        store.add("c1", unit(1.0))
        assert store.query(np.zeros(DIM, dtype=np.float32), k=5, threshold=0.1) == []

    def test_zero_stored_vector_never_matches(self, store):
        store.add("zero", np.zeros(DIM, dtype=np.float32))
        store.add("real", unit(1.0))

        results = store.query(unit(1.0), k=5, threshold=0.1)
        assert [r.case_id for r in results] == ["real"]

    def test_nan_in_query_is_neutralised(self, store):
        store.add("c1", unit(1.0))
        query = unit(1.0)
        query[3] = np.nan

        results = store.query(query, k=5, threshold=0.0)
        assert all(np.isfinite(r.similarity_score) for r in results)

    def test_infinity_in_stored_vector_is_neutralised(self, store):
        vector = unit(1.0)
        vector[2] = np.inf
        store.add("c1", vector)

        results = store.query(unit(1.0), k=5, threshold=0.0)
        assert all(np.isfinite(r.similarity_score) for r in results)

    def test_wrong_dimension_still_raises(self, store):
        with pytest.raises(ValueError, match="dimension mismatch"):
            store.add("c1", np.ones(DIM + 1, dtype=np.float32))

    def test_k_larger_than_store_returns_everything(self, store):
        store.add("c1", unit(1.0))
        store.add("c2", unit(0.0, 1.0))
        assert len(store.query(unit(1.0), k=50, threshold=0.0)) == 2

    def test_k_of_zero_returns_empty(self, store):
        store.add("c1", unit(1.0))
        assert store.query(unit(1.0), k=0, threshold=0.0) == []

    def test_threshold_above_every_score_returns_empty(self, store):
        store.add("c1", unit(0.0, 1.0))
        assert store.query(unit(1.0), k=5, threshold=0.99) == []

    def test_query_on_empty_store_returns_empty(self, store):
        assert store.query(unit(1.0), k=5, threshold=0.0) == []


class TestPreservedBehaviour:
    def test_metadata_is_copied_not_aliased(self, store):
        original = {"priority": "high"}
        store.add("c1", unit(1.0), original)

        result = store.query(unit(1.0), k=1, threshold=0.0)[0]
        result.metadata["priority"] = "low"

        assert store.get("c1")[1]["priority"] == "high"
        assert original["priority"] == "high"

    def test_get_returns_the_raw_unnormalised_vector(self, store):
        vector = np.full(DIM, 3.0, dtype=np.float32)
        store.add("c1", vector)

        stored, _ = store.get("c1")
        np.testing.assert_allclose(stored, vector)

    def test_update_metadata_merges(self, store):
        store.add("c1", unit(1.0), {"a": 1})
        assert store.update_metadata("c1", {"b": 2}) is True
        assert store.get("c1")[1] == {"a": 1, "b": 2}

    def test_stats_track_adds_queries_and_evictions(self):
        store = VectorStore(embedding_dim=DIM, maxsize=2, similarity_threshold=0.0)
        store.add("c1", unit(1.0))
        store.add("c2", unit(0.0, 1.0))
        store.add("c3", unit(0.0, 0.0, 1.0))
        store.query(unit(1.0), k=1, threshold=0.0)

        stats = store.get_stats()
        assert stats["total_added"] == 3
        assert stats["total_evicted"] == 1
        assert stats["total_queries"] == 1
        assert stats["current_size"] == 2


class TestConcurrency:
    def test_concurrent_adds_and_queries_stay_consistent(self, store):
        rng = np.random.default_rng(5)
        errors = []

        def writer(offset: int) -> None:
            try:
                for i in range(30):
                    store.add(f"w{offset}_{i}", rng.standard_normal(DIM).astype(np.float32))
            except Exception as exc:  # pragma: no cover - surfaced via assertion
                errors.append(exc)

        def reader() -> None:
            try:
                for _ in range(30):
                    store.query(rng.standard_normal(DIM).astype(np.float32), k=5, threshold=0.0)
            except Exception as exc:  # pragma: no cover - surfaced via assertion
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(o,)) for o in range(3)]
        threads += [threading.Thread(target=reader) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        assert store.size() == len(store._row_of)
        assert len(set(store._row_of.values())) == len(store._row_of)


class TestVectorisation:
    def test_query_does_not_call_the_per_pair_helper(self, store, monkeypatch):
        """The scan is gone, not merely faster.

        The old loop called _cosine_similarity once per stored embedding; the
        replacement performs a single matrix product, so the helper must not be
        touched at all during a query.
        """
        for i in range(50):
            store.add(f"c{i}", unit(1.0, i))

        calls = 0
        original = VectorStore._cosine_similarity

        def counting(a, b):
            nonlocal calls
            calls += 1
            return original(a, b)

        monkeypatch.setattr(VectorStore, "_cosine_similarity", staticmethod(counting))

        store.query(unit(1.0), k=5, threshold=0.0)
        assert calls == 0

        store.query_batch(np.stack([unit(1.0), unit(0.0, 1.0)]), k=5, threshold=0.0)
        assert calls == 0
