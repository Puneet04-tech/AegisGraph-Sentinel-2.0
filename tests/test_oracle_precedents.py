"""Unit tests for precedent-case citation in AegisOracle explanations.

A fake embedder maps explanation text to fixed directions by decision
keyword ('block' / 'review' / other), so semantic similarity between
cases is fully controlled: same-category cases are near-identical,
cross-category cases are orthogonal (similarity ~0).
"""
from __future__ import annotations

import numpy as np
import pytest

from src.case_management.retriever import CaseRetriever
from src.case_management.vector_store import VectorStore

# The oracle module imports torch; skip cleanly where it is unavailable
try:
    from src.inference.explainer import AegisOracle
    ORACLE_AVAILABLE = True
except ImportError:
    ORACLE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not ORACLE_AVAILABLE, reason="PyTorch not installed")

EMBEDDING_DIM = 4


class FakeEmbedder:
    """Deterministic embedder keyed on decision words in the text."""

    embedding_dim = EMBEDDING_DIM

    def _vector(self, text: str) -> np.ndarray:
        text = text.lower()
        if "block" in text:
            base = np.array([1.0, 0.0, 0.0, 0.0])
        elif "review" in text:
            base = np.array([0.0, 1.0, 0.0, 0.0])
        else:
            base = np.array([0.0, 0.0, 1.0, 0.0])
        # Deterministic jitter so same-category texts are similar, not identical
        jitter = (len(text) % 7) * 0.01
        vector = base + np.array([0.0, 0.0, 0.0, jitter])
        return (vector / np.linalg.norm(vector)).astype(np.float32)

    def embed_case_explanation(self, explanation: dict) -> np.ndarray:
        combined = " ".join(
            str(explanation.get(key, ""))
            for key in ("summary", "explanation", "factors")
        )
        return self._vector(combined)

    def embed_text(self, text: str) -> np.ndarray:
        return self._vector(text)

    def get_cache_stats(self) -> dict:
        return {}


class FailingEmbedder(FakeEmbedder):
    def embed_case_explanation(self, explanation: dict) -> np.ndarray:
        raise RuntimeError("embedding service down")


def _retriever(embedder=None):
    return CaseRetriever(
        embedder=embedder or FakeEmbedder(),
        vector_store=VectorStore(
            embedding_dim=EMBEDDING_DIM, similarity_threshold=0.0
        ),
    )


def _transaction(txn_id: str) -> dict:
    return {
        "transaction_id": txn_id,
        "source_account": "ACC-A",
        "target_account": "ACC-B",
        "amount": 100000,
    }


def _risk_result(decision: str = "BLOCK") -> dict:
    return {
        "risk_score": 0.94,
        "decision": decision,
        "breakdown": {"graph": 0.91},
        "confidence": 0.96,
    }


def _seed_blocked_case(retriever, case_id: str, n: int = 1):
    """Index a past confirmed blocked-mule case."""
    retriever.index_case(
        case_id=case_id,
        explanation={
            "summary": f"Transaction blocked: mule chain variant {n}",
            "explanation": "Blocked high-risk mule network transfer",
            "factors": ["Suspicious network structure"],
        },
        metadata={"decision": "BLOCK", "status": "CONFIRMED"},
    )


def _seed_review_case(retriever, case_id: str):
    retriever.index_case(
        case_id=case_id,
        explanation={
            "summary": "Transaction flagged for review: velocity anomaly",
            "explanation": "Under review for rapid transfers",
            "factors": ["High transaction velocity"],
        },
        metadata={"decision": "REVIEW", "status": "CONFIRMED"},
    )


class TestPrecedentCitation:
    def test_similar_past_cases_cited(self):
        retriever = _retriever()
        _seed_blocked_case(retriever, "CASE-B1", n=1)
        _seed_blocked_case(retriever, "CASE-B2", n=2)
        _seed_review_case(retriever, "CASE-R1")

        oracle = AegisOracle(case_retriever=retriever)
        report = oracle.explain_decision(_transaction("TXN-NEW"), _risk_result())

        cited_ids = {p["case_id"] for p in report["precedent_cases"]}
        assert cited_ids == {"CASE-B1", "CASE-B2"}
        assert "Precedent Cases" in report["explanation"]

    def test_precedents_sorted_by_similarity(self):
        retriever = _retriever()
        for i in range(3):
            _seed_blocked_case(retriever, f"CASE-B{i}", n=i)

        oracle = AegisOracle(case_retriever=retriever)
        report = oracle.explain_decision(_transaction("TXN-NEW"), _risk_result())

        similarities = [p["similarity"] for p in report["precedent_cases"]]
        assert similarities == sorted(similarities, reverse=True)

    def test_dissimilar_cases_not_cited(self):
        retriever = _retriever()
        _seed_review_case(retriever, "CASE-R1")

        oracle = AegisOracle(case_retriever=retriever)
        report = oracle.explain_decision(_transaction("TXN-NEW"), _risk_result())

        assert report["precedent_cases"] == []
        assert "Precedent Cases" not in report["explanation"]

    def test_top_k_cap(self):
        retriever = _retriever()
        for i in range(5):
            _seed_blocked_case(retriever, f"CASE-B{i}", n=i)

        oracle = AegisOracle(case_retriever=retriever)
        report = oracle.explain_decision(_transaction("TXN-NEW"), _risk_result())

        assert len(report["precedent_cases"]) == AegisOracle.PRECEDENT_TOP_K

    def test_precedent_entry_fields(self):
        retriever = _retriever()
        _seed_blocked_case(retriever, "CASE-B1")

        oracle = AegisOracle(case_retriever=retriever)
        report = oracle.explain_decision(_transaction("TXN-NEW"), _risk_result())
        precedent = report["precedent_cases"][0]

        assert precedent["case_id"] == "CASE-B1"
        assert 0.0 < precedent["similarity"] <= 1.0
        assert precedent["similarity_percent"].endswith("%")
        assert precedent["decision"] == "BLOCK"
        assert precedent["status"] == "CONFIRMED"
        assert "mule chain" in precedent["summary"]


class TestIndexingLifecycle:
    def test_explained_case_indexed_for_future_citation(self):
        retriever = _retriever()
        oracle = AegisOracle(case_retriever=retriever)

        first = oracle.explain_decision(_transaction("TXN-1"), _risk_result())
        assert first["precedent_cases"] == []

        second = oracle.explain_decision(_transaction("TXN-2"), _risk_result())
        cited_ids = {p["case_id"] for p in second["precedent_cases"]}

        assert cited_ids == {"TXN-1"}
        assert retriever.vector_store.size() == 2

    def test_reexplained_case_never_cites_itself(self):
        retriever = _retriever()
        oracle = AegisOracle(case_retriever=retriever)

        oracle.explain_decision(_transaction("TXN-1"), _risk_result())
        again = oracle.explain_decision(_transaction("TXN-1"), _risk_result())

        assert all(
            p["case_id"] != "TXN-1" for p in again["precedent_cases"]
        )

    def test_indexed_metadata_recorded(self):
        retriever = _retriever()
        oracle = AegisOracle(case_retriever=retriever)
        oracle.explain_decision(_transaction("TXN-1"), _risk_result())

        _, metadata = retriever.vector_store.get("TXN-1")
        assert metadata["decision"] == "BLOCK"
        assert metadata["status"] == "UNREVIEWED"
        assert "date" in metadata
        assert "summary" in metadata


class TestRobustness:
    def test_backward_compatible_without_retriever(self):
        oracle = AegisOracle()
        report = oracle.explain_decision(_transaction("TXN-1"), _risk_result())

        assert "precedent_cases" not in report
        assert "Precedent Cases" not in report["explanation"]

    def test_retrieval_failure_degrades_gracefully(self):
        retriever = _retriever(embedder=FailingEmbedder())
        oracle = AegisOracle(case_retriever=retriever)

        report = oracle.explain_decision(_transaction("TXN-1"), _risk_result())

        # The explanation itself must survive a broken precedent index
        assert report["decision"] == "BLOCK"
        assert "precedent_cases" not in report
