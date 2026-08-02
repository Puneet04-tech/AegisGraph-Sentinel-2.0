"""
Regression tests for CaseRetriever similarity threshold handling.

Covers two fixed defects:
1. ``CaseRetriever(similarity_threshold=...)`` was silently ignored: all query
   methods passed ``threshold=None`` through to the vector store, whose internal
   default is ``0.0``, so orthogonal (zero-similarity) cases were returned even
   when a meaningful threshold was configured. Explicitly configured thresholds
   are now honored, while the default remains ``0.0`` to preserve the existing
   top-k behavior of the RAG workflow.
2. ``index_case`` mutated the caller's metadata dict in place by calling
   ``update()`` on the original object.
3. ``update_case_metadata`` left the internal case registry stale.

These tests pin the corrected behavior with deterministic fake embeddings.
"""

import numpy as np
import pytest

from src.case_management.retriever import CaseRetriever
from src.case_management.vector_store import VectorStore


class FakeEmbedder:
    """Deterministic embedder that maps a key to a fixed unit vector."""

    def __init__(self, vectors):
        self.vectors = vectors
        self._cache_hits = 0

    def embed_text(self, text):
        return np.array(self.vectors[text], dtype=np.float32)

    def embed_case_explanation(self, explanation):
        return np.array(self.vectors[explanation["summary"]], dtype=np.float32)

    def get_cache_stats(self):
        return {"cache_hits": self._cache_hits, "cache_size": len(self.vectors)}

    def clear_cache(self):
        self._cache_hits = 0


@pytest.fixture
def embedder():
    # q1 is identical to CASE_A; CASE_C is at 0.6 similarity to q1;
    # CASE_B is orthogonal (similarity 0.0).
    return FakeEmbedder(
        {
            "q1": [1.0, 0.0, 0.0, 0.0],
            "CASE_A": [1.0, 0.0, 0.0, 0.0],
            "CASE_B": [0.0, 1.0, 0.0, 0.0],
            "CASE_C": [0.6, 0.8, 0.0, 0.0],
        }
    )


@pytest.fixture
def retriever(embedder):
    return CaseRetriever(embedder=embedder, embedding_dim=4, similarity_threshold=0.8)


@pytest.fixture
def populated(retriever):
    retriever.index_case("CASE_A", {"summary": "CASE_A"}, {"priority": "HIGH"})
    retriever.index_case("CASE_B", {"summary": "CASE_B"}, {"priority": "LOW"})
    retriever.index_case("CASE_C", {"summary": "CASE_C"}, {"priority": "MEDIUM"})
    return retriever


class TestConfiguredThreshold:
    """The constructor threshold must actually be applied to queries."""

    def test_default_threshold_is_zero(self, embedder):
        retriever = CaseRetriever(embedder=embedder, embedding_dim=4)
        assert retriever.similarity_threshold == 0.0

    def test_default_preserves_top_k_behavior(self, embedder):
        retriever = CaseRetriever(embedder=embedder, embedding_dim=4)
        retriever.index_case("CASE_A", {"summary": "CASE_A"})
        retriever.index_case("CASE_B", {"summary": "CASE_B"})
        results = retriever.find_similar("q1", k=10)
        assert {r["case_id"] for r in results} == {"CASE_A", "CASE_B"}

    def test_vector_store_default_uses_configured_threshold(self, retriever):
        assert retriever.vector_store.similarity_threshold == pytest.approx(0.8)

    def test_find_similar_filters_below_configured_threshold(self, populated):
        results = populated.find_similar("q1", k=10)
        case_ids = {r["case_id"] for r in results}
        assert case_ids == {"CASE_A"}
        assert results[0]["case_id"] == "CASE_A"
        assert results[0]["similarity"] == pytest.approx(1.0)

    def test_find_similar_drops_orthogonal_result(self, populated):
        results = populated.find_similar("q1", k=10)
        assert all(r["similarity"] >= 0.8 for r in results)

    def test_find_similar_by_case_honors_configured_threshold(self, populated):
        # CASE_C sits at exactly 0.6 similarity to CASE_A: filtered by 0.8.
        results = populated.find_similar_by_case("CASE_A", k=10, exclude_self=True)
        assert results == []

    def test_find_similar_by_explanation_honors_configured_threshold(self, populated):
        results = populated.find_similar_by_explanation({"summary": "q1"}, k=10)
        assert {r["case_id"] for r in results} == {"CASE_A"}

    def test_lower_threshold_keeps_more_results(self, populated):
        # A threshold below 0.6 must admit CASE_C as well.
        low = CaseRetriever(
            embedder=populated.embedder,
            embedding_dim=4,
            similarity_threshold=0.5,
        )
        low.index_case("CASE_A", {"summary": "CASE_A"})
        low.index_case("CASE_C", {"summary": "CASE_C"})
        results = low.find_similar("q1", k=10)
        assert {r["case_id"] for r in results} == {"CASE_A", "CASE_C"}

    def test_threshold_applies_to_insights(self, populated):
        insights = populated.get_investigation_insights("CASE_A", top_k=5)
        # No related cases survive the 0.8 threshold (only self is similar),
        # so the fallback recommendation is returned.
        assert insights["similar_case_count"] == 0
        assert "Continue monitoring" in insights["recommendations"][0]


class TestExplicitThresholdOverride:
    """Per-call thresholds must override the configured default."""

    def test_explicit_low_threshold_overrides(self, populated):
        results = populated.find_similar("q1", k=10, threshold=0.0)
        assert {r["case_id"] for r in results} == {"CASE_A", "CASE_B", "CASE_C"}

    def test_explicit_high_threshold_overrides(self, populated):
        results = populated.find_similar("q1", k=10, threshold=0.95)
        assert len(results) == 1

    def test_by_case_explicit_threshold(self, populated):
        results = populated.find_similar_by_case(
            "CASE_A", k=10, exclude_self=True, threshold=0.5
        )
        assert {r["case_id"] for r in results} == {"CASE_C"}

    def test_by_explanation_explicit_threshold(self, populated):
        results = populated.find_similar_by_explanation(
            {"summary": "q1"}, k=10, threshold=0.5
        )
        assert {r["case_id"] for r in results} == {"CASE_A", "CASE_C"}


class TestMetadataIsolation:
    """index_case must not mutate the caller's metadata dict."""

    def test_original_metadata_untouched(self, retriever):
        meta = {"priority": "LOW", "owner": "analyst-1"}
        retriever.index_case("CASE_X", {"summary": "CASE_A"}, meta)
        assert meta == {"priority": "LOW", "owner": "analyst-1"}

    def test_stored_metadata_has_indexed_at_and_summary(self, retriever):
        retriever.index_case("CASE_X", {"summary": "CASE_A"}, {"priority": "HIGH"})
        _, stored = retriever.vector_store.get("CASE_X")
        assert stored["priority"] == "HIGH"
        assert stored["summary"] == "CASE_A"
        assert "indexed_at" in stored

    def test_none_metadata_creates_fresh_dict(self, retriever):
        retriever.index_case("CASE_X", {"summary": "CASE_A"})
        _, stored = retriever.vector_store.get("CASE_X")
        assert stored["summary"] == "CASE_A"
        assert "indexed_at" in stored

    def test_batch_index_does_not_mutate_inputs(self, retriever):
        cases = [
            {
                "case_id": "CASE_A",
                "explanation": {"summary": "CASE_A"},
                "metadata": {"priority": "HIGH"},
            },
            {
                "case_id": "CASE_B",
                "explanation": {"summary": "CASE_B"},
                "metadata": {"priority": "LOW"},
            },
        ]
        retriever.index_cases_batch(cases)
        assert cases[0]["metadata"] == {"priority": "HIGH"}
        assert cases[1]["metadata"] == {"priority": "LOW"}

    def test_update_metadata_does_not_leak_between_cases(self, populated):
        populated.update_case_metadata("CASE_A", {"status": "RESOLVED"})
        _, meta_b = populated.vector_store.get("CASE_B")
        assert "status" not in meta_b
        _, meta_c = populated.vector_store.get("CASE_C")
        assert "status" not in meta_c

    def test_registry_metadata_matches_store(self, populated):
        populated.update_case_metadata("CASE_A", {"status": "RESOLVED"})
        assert populated._case_registry["CASE_A"]["metadata"]["status"] == "RESOLVED"


class TestResolveThreshold:
    """The _resolve_threshold helper behaves as expected."""

    def test_none_falls_back_to_configured(self, retriever):
        assert retriever._resolve_threshold(None) == pytest.approx(0.8)

    def test_explicit_value_wins(self, retriever):
        assert retriever._resolve_threshold(0.3) == pytest.approx(0.3)

    def test_zero_is_honored(self, retriever):
        assert retriever._resolve_threshold(0.0) == 0.0


class TestQueryResultsAreCopies:
    """Search result metadata must not alias the stored dict."""

    def test_result_metadata_does_not_share_identity(self, populated):
        results = populated.find_similar("q1", k=10, threshold=0.0)
        stored_a = populated.vector_store.get("CASE_A")[1]
        for result in results:
            if result["case_id"] == "CASE_A":
                assert result["metadata"] is not stored_a

    def test_get_metadata_is_copy(self, populated):
        stored_a = populated.vector_store.get("CASE_A")
        stored_a[1]["tampered"] = True
        again = populated.vector_store.get("CASE_A")[1]
        assert "tampered" not in again


class TestCustomVectorStorePassthrough:
    """A caller-supplied vector store keeps its own threshold as fallback."""

    def test_custom_store_threshold_wins_when_retriever_has_high_default(self, embedder):
        custom_store = VectorStore(embedding_dim=4, similarity_threshold=0.0)
        retriever = CaseRetriever(
            embedder=embedder,
            vector_store=custom_store,
            embedding_dim=4,
            similarity_threshold=0.9,
        )
        retriever.index_case("CASE_A", {"summary": "CASE_A"})
        retriever.index_case("CASE_B", {"summary": "CASE_B"})
        # Explicit threshold None -> retriever default 0.9, so CASE_B is dropped.
        results = retriever.find_similar("q1", k=10)
        assert {r["case_id"] for r in results} == {"CASE_A"}
        # But the store itself still answers unthresholded lookups.
        assert custom_store.similarity_threshold == 0.0
