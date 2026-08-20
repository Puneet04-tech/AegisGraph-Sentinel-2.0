"""
Tests for VectorStore metadata isolation and storage semantics.

Regression coverage for the metadata aliasing bug: `add` stored the
caller's metadata dict by reference and `update_metadata` mutated it in
place, so a caller reusing one dict across cases (or the `[{}] * n`
default in `add_batch`) caused metadata updates on one case to leak
into every other case that aliased the same object.
"""

import numpy as np
import pytest

from src.case_management.vector_store import VectorStore, SearchResult


@pytest.fixture
def store():
    return VectorStore(embedding_dim=3, maxsize=100, similarity_threshold=0.5)


def make_embeddings(n, dim=3, seed=0):
    rng = np.random.RandomState(seed)
    return rng.rand(n, dim)


class TestMetadataIsolation:
    """Metadata must never be shared or aliased between cases."""

    def test_reused_dict_does_not_alias_cases(self, store):
        shared = {"priority": "LOW"}
        store.add("case-1", np.array([1.0, 0.0, 0.0]), shared)
        store.add("case-2", np.array([0.0, 1.0, 0.0]), shared)

        store.update_metadata("case-1", {"status": "CLOSED"})

        assert store._embeddings["case-1"][1] == {"priority": "LOW", "status": "CLOSED"}
        assert store._embeddings["case-2"][1] == {"priority": "LOW"}

    def test_update_does_not_mutate_caller_dict(self, store):
        shared = {"priority": "LOW"}
        store.add("case-1", np.array([1.0, 0.0, 0.0]), shared)

        store.update_metadata("case-1", {"status": "CLOSED"})

        assert shared == {"priority": "LOW"}

    def test_stored_metadata_is_a_copy(self, store):
        metadata = {"priority": "LOW"}
        store.add("case-1", np.array([1.0, 0.0, 0.0]), metadata)

        metadata["priority"] = "CRITICAL"

        assert store._embeddings["case-1"][1] == {"priority": "LOW"}

    def test_get_returns_independent_copy(self, store):
        store.add("case-1", np.array([1.0, 0.0, 0.0]), {"priority": "LOW"})

        _, returned = store.get("case-1")
        returned["priority"] = "CRITICAL"

        assert store._embeddings["case-1"][1] == {"priority": "LOW"}

    def test_query_results_are_independent_copies(self, store):
        store.add("case-1", np.array([1.0, 0.0, 0.0]), {"priority": "LOW"})

        results = store.query(np.array([1.0, 0.0, 0.0]), k=5)
        results[0].metadata["priority"] = "CRITICAL"

        assert store._embeddings["case-1"][1] == {"priority": "LOW"}


class TestBatchMetadata:
    """add_batch must give every case a distinct metadata dict."""

    def test_batch_default_metadata_are_distinct(self, store):
        ids = ["c1", "c2", "c3"]
        store.add_batch(ids, make_embeddings(3))

        store.update_metadata("c1", {"priority": "HIGH"})

        assert store._embeddings["c1"][1] == {"priority": "HIGH"}
        assert store._embeddings["c2"][1] == {}
        assert store._embeddings["c3"][1] == {}

    def test_batch_with_provided_metadatas(self, store):
        ids = ["c1", "c2"]
        metadatas = [{"priority": "HIGH"}, {"priority": "LOW"}]
        store.add_batch(ids, make_embeddings(2), metadatas)

        assert store._embeddings["c1"][1] == {"priority": "HIGH"}
        assert store._embeddings["c2"][1] == {"priority": "LOW"}

    def test_batch_metadata_list_aliasing_isolated(self, store):
        shared = {"team": "fraud"}
        store.add_batch(["c1", "c2"], make_embeddings(2), [shared, shared])

        store.update_metadata("c1", {"owner": "analyst1"})

        assert store._embeddings["c2"][1] == {"team": "fraud"}

    def test_batch_empty_ids(self, store):
        store.add_batch([], np.zeros((0, 3)))
        assert store.size() == 0


class TestUpdateMetadata:
    """update_metadata semantics."""

    def test_merge_replaces_overlapping_keys(self, store):
        store.add("case-1", np.array([1.0, 0.0, 0.0]), {"priority": "LOW", "team": "fraud"})

        assert store.update_metadata("case-1", {"priority": "HIGH"}) is True

        assert store._embeddings["case-1"][1] == {"priority": "HIGH", "team": "fraud"}

    def test_update_missing_case_returns_false(self, store):
        assert store.update_metadata("missing", {"priority": "HIGH"}) is False

    def test_update_keeps_embedding(self, store):
        embedding = np.array([1.0, 0.0, 0.0])
        store.add("case-1", embedding, {"priority": "LOW"})

        store.update_metadata("case-1", {"status": "OPEN"})

        assert np.array_equal(store._embeddings["case-1"][0], embedding)


class TestAddSemantics:
    """add dimension validation and overwrite behavior."""

    def test_dimension_mismatch_raises(self, store):
        with pytest.raises(ValueError):
            store.add("case-1", np.array([1.0, 0.0]), {})

    def test_add_overwrites_existing(self, store):
        store.add("case-1", np.array([1.0, 0.0, 0.0]), {"priority": "LOW"})
        store.add("case-1", np.array([1.0, 0.0, 0.0]), {"priority": "HIGH"})

        assert store._embeddings["case-1"][1] == {"priority": "HIGH"}
        assert store.size() == 1

    def test_batch_dimension_mismatch_raises(self, store):
        with pytest.raises(ValueError):
            store.add_batch(["c1", "c2"], np.zeros((2, 2)))

    def test_batch_count_mismatch_raises(self, store):
        with pytest.raises(ValueError):
            store.add_batch(["c1", "c2", "c3"], make_embeddings(2))


class TestLRUEviction:
    """LRU eviction must respect maxsize."""

    def test_eviction_removes_oldest(self):
        small = VectorStore(embedding_dim=3, maxsize=2)
        small.add("a", np.array([1.0, 0.0, 0.0]), {})
        small.add("b", np.array([0.0, 1.0, 0.0]), {})
        small.add("c", np.array([0.0, 0.0, 1.0]), {})

        assert small.size() == 2
        assert "a" not in small._embeddings
        assert "b" in small._embeddings
        assert "c" in small._embeddings

    def test_get_marks_recently_used(self):
        small = VectorStore(embedding_dim=3, maxsize=2)
        small.add("a", np.array([1.0, 0.0, 0.0]), {})
        small.add("b", np.array([0.0, 1.0, 0.0]), {})

        small.get("a")
        small.add("c", np.array([0.0, 0.0, 1.0]), {})

        assert "a" in small._embeddings
        assert "b" not in small._embeddings

    def test_stats_track_evictions(self):
        small = VectorStore(embedding_dim=3, maxsize=2)
        for i in range(5):
            small.add(f"c{i}", np.full(3, i + 1.0), {})

        stats = small.get_stats()
        assert stats["total_evicted"] == 3
        assert stats["current_size"] == 2


class TestSimilaritySearch:
    """Cosine similarity search behavior."""

    def test_identical_vectors_similarity_one(self, store):
        store.add("case-1", np.array([1.0, 0.0, 0.0]), {})

        results = store.query(np.array([1.0, 0.0, 0.0]), k=5)

        assert len(results) == 1
        assert results[0].case_id == "case-1"
        assert results[0].similarity_score == pytest.approx(1.0)

    def test_orthogonal_vectors_below_threshold(self, store):
        store.add("case-1", np.array([1.0, 0.0, 0.0]), {})

        results = store.query(np.array([0.0, 1.0, 0.0]), k=5)

        assert results == []

    def test_query_threshold_override(self, store):
        store.add("case-1", np.array([1.0, 0.0, 0.0]), {})

        permissive = store.query(np.array([0.7071, 0.7071, 0.0]), k=5, threshold=0.1)
        strict = store.query(np.array([0.7071, 0.7071, 0.0]), k=5, threshold=0.99)

        assert len(permissive) == 1
        assert strict == []

    def test_results_sorted_highest_first(self, store):
        store.add("near", np.array([1.0, 0.0, 0.0]), {})
        store.add("far", np.array([0.0, 1.0, 0.0]), {})
        store.add("mid", np.array([1.0, 1.0, 0.0]), {})

        results = store.query(np.array([1.0, 0.0, 0.0]), k=5, threshold=0.1)

        scores = [r.similarity_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_k_limits_results(self, store):
        store.add_batch(["c1", "c2", "c3"], np.eye(3))

        results = store.query(np.ones(3) / np.sqrt(3), k=2, threshold=0.1)

        assert len(results) == 2

    def test_query_empty_store_returns_empty(self, store):
        assert store.query(np.ones(3), k=5) == []

    def test_query_batch_shape(self, store):
        store.add_batch(["c1", "c2"], np.eye(3)[:2, :])

        results = store.query_batch(np.eye(3)[:2, :], k=1)

        assert len(results) == 2
        assert all(len(r) == 1 for r in results)
        assert results[0][0].case_id == "c1"
        assert results[1][0].case_id == "c2"

    def test_zero_vector_similarity_zero(self, store):
        store.add("case-1", np.array([1.0, 0.0, 0.0]), {})

        results = store.query(np.zeros(3), k=5)

        assert results == []


class TestStoreStats:
    """Store statistics."""

    def test_stats_counts(self, store):
        store.add("a", np.array([1.0, 0.0, 0.0]), {})
        store.add("b", np.array([0.0, 1.0, 0.0]), {})
        store.query(np.array([1.0, 0.0, 0.0]), k=5)

        stats = store.get_stats()
        assert stats["total_added"] == 2
        assert stats["total_queries"] == 1
        assert stats["current_size"] == 2

    def test_remove_semantics(self, store):
        store.add("a", np.array([1.0, 0.0, 0.0]), {})

        assert store.remove("a") is True
        assert store.remove("a") is False
        assert store.size() == 0

    def test_clear(self, store):
        store.add_batch(["c1", "c2"], np.eye(3)[:2, :])
        store.clear()
        assert store.size() == 0
