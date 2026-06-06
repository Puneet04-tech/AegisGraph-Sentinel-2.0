"""Regression tests for the production batch scorer."""

from __future__ import annotations

import os

import pytest

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

# Handle optional torch dependency
try:
    from src.inference.production_scorer import FraudScore, ProductionRiskScorer
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

pytestmark = pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not installed")

if not TORCH_AVAILABLE:
    pytest.skip(allow_module_level=True)


class _DummyModel:
    def eval(self):
        return self


class _RecordingFuture:
    def __init__(self, fn, args, kwargs, on_result):
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self._on_result = on_result
        self._resolved = False
        self._result = None

    def result(self):
        if not self._resolved:
            try:
                self._result = self._fn(*self._args, **self._kwargs)
            finally:
                self._on_result()
            self._resolved = True
        return self._result


class _RecordingExecutor:
    def __init__(self, max_workers):
        self.max_workers = max_workers
        self.pending = 0
        self.peak_pending = 0
        self.submitted = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def submit(self, fn, *args, **kwargs):
        self.submitted += 1
        self.pending += 1
        self.peak_pending = max(self.peak_pending, self.pending)
        return _RecordingFuture(fn, args, kwargs, self._mark_complete)

    def _mark_complete(self):
        self.pending -= 1


def _make_score(transaction_id: str) -> FraudScore:
    return FraudScore(
        transaction_id=transaction_id,
        risk_score=0.1,
        decision="ALLOW",
        confidence=0.9,
        explanation="ok",
        breakdown={"graph_risk": 0.1},
        influential_neighbors=[],
        model_version="2.0.0",
        inference_time_ms=1.0,
        graph_size=1,
    )


def test_score_batch_processes_transactions_in_bounded_chunks(monkeypatch):
    executors = []
    batch_sizes = []

    def fake_thread_pool_executor(*, max_workers):
        executor = _RecordingExecutor(max_workers)
        executors.append(executor)
        return executor

    def fake_as_completed(futures):
        futures = list(futures)
        batch_sizes.append(len(futures))
        executor = executors[-1]
        assert len(futures) <= executor.max_workers
        assert executor.pending == len(futures)
        return iter(futures)

    monkeypatch.setattr("src.inference.production_scorer.ThreadPoolExecutor", fake_thread_pool_executor)
    monkeypatch.setattr("src.inference.production_scorer.as_completed", fake_as_completed)

    scorer = ProductionRiskScorer(model=_DummyModel(), graph_constructor=object())
    scorer.score_transaction = lambda transaction, reference_time=None, k_hops=2, _subgraph_cache=None: _make_score(
        transaction["transaction_id"]
    )

    transactions = [
        {"transaction_id": f"txn-{index}", "source_account": f"acct-{index}"}
        for index in range(5)
    ]

    scores = scorer.score_batch(transactions, batch_size=2)

    assert [score.transaction_id for score in scores] == [txn["transaction_id"] for txn in transactions]
    assert executors[-1].submitted == len(transactions)
    assert executors[-1].peak_pending == 2
    assert batch_sizes == [2, 2, 1]
