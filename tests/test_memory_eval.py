import pytest
from src.eval.memory_eval import DynamicBatchEvaluator


def test_dynamic_batch_evaluator_initialization():
    evaluator = DynamicBatchEvaluator(initial_batch_size=128, min_batch_size=16)
    assert evaluator.current_batch_size == 128
    assert evaluator.min_batch_size == 16


def test_reduce_batch_size_halves_size():
    evaluator = DynamicBatchEvaluator(initial_batch_size=64, min_batch_size=16)
    new_size = evaluator.reduce_batch_size()
    assert new_size == 32
    assert evaluator.current_batch_size == 32


def test_evaluate_batches_handles_simulated_oom():
    evaluator = DynamicBatchEvaluator(initial_batch_size=32, min_batch_size=8)
    items = list(range(100))

    call_count = 0

    def mock_eval(batch):
        nonlocal call_count
        call_count += 1
        # Simulate OOM on first call with batch size 32
        if len(batch) > 16:
            raise RuntimeError("CUDA out of memory")
        return len(batch)

    results = evaluator.evaluate_batches(items, mock_eval)
    assert sum(results) == 100
    assert evaluator.current_batch_size <= 16
