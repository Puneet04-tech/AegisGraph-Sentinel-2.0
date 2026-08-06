"""Unit tests for bulk operation helpers."""

import pytest

from src.utils.bulk_operations import (
    chunked,
    execute_with_retry_per_item,
    process_in_batches,
    summarize_results,
)


class TestChunked:
    def test_returns_equal_chunks_and_partial_tail(self):
        assert list(chunked([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]

    def test_size_greater_than_length_yields_single_chunk(self):
        assert list(chunked([1, 2, 3], 10)) == [[1, 2, 3]]

    def test_size_equal_to_length_yields_single_full_chunk(self):
        assert list(chunked([1, 2, 3], 3)) == [[1, 2, 3]]

    def test_empty_input_yields_nothing(self):
        assert list(chunked([], 5)) == []

    def test_invalid_size_raises_value_error(self):
        with pytest.raises(ValueError):
            list(chunked([1, 2, 3], 0))
        with pytest.raises(ValueError):
            list(chunked([1, 2, 3], -1))

    def test_works_with_generator(self):
        generator = (n * n for n in range(5))
        assert list(chunked(generator, 2)) == [[0, 1], [4, 9], [16]]

    def test_chunks_are_lists_not_iterators(self):
        for batch in chunked((n for n in range(3)), 2):
            assert isinstance(batch, list)


class TestProcessInBatches:
    def test_applies_func_per_batch_in_order(self):
        results = process_in_batches(range(6), 3, sum)
        assert results == [3, 12]

    def test_handles_odd_remainder(self):
        results = process_in_batches(range(7), 3, len)
        assert results == [3, 3, 1]

    def test_func_receives_chunk_contents(self):
        seen = []
        process_in_batches([1, 2, 3, 4], 2, lambda batch: seen.append(batch))
        assert seen == [[1, 2], [3, 4]]

    def test_empty_input_returns_no_results(self):
        assert process_in_batches([], 4, sum) == []


class TestExecuteWithRetryPerItem:
    def test_all_succeed_returns_full_success_list(self):
        def ok(item):
            return item * 2

        result = execute_with_retry_per_item([1, 2, 3], ok)
        assert result["success"] == [2, 4, 6]
        assert result["failed"] == []

    def test_retries_item_that_fails_then_succeeds(self):
        attempts = {"counter": 0}

        def flaky(item):
            if item == "retry-me" and attempts["counter"] == 0:
                attempts["counter"] += 1
                raise RuntimeError("transient")
            return f"ok-{item}"

        result = execute_with_retry_per_item(
            ["a", "retry-me", "b"], flaky, max_attempts=3
        )
        assert result["success"] == ["ok-a", "ok-retry-me", "ok-b"]
        assert result["failed"] == []
        assert attempts["counter"] == 1

    def test_item_exhausting_attempts_lands_in_failed(self):
        def always_boom(item):
            raise ValueError(f"bad {item}")

        result = execute_with_retry_per_item([1, 2], always_boom, max_attempts=2)
        assert result["success"] == []
        assert len(result["failed"]) == 2
        assert result["failed"][0]["item"] == 1
        assert "bad 1" in result["failed"][0]["error"]

    def test_mixed_outcomes_partition_items_exactly_once(self):
        def mixed(item):
            if item % 2 == 0:
                raise KeyError(str(item))
            return item

        result = execute_with_retry_per_item([1, 2, 3, 4], mixed)
        assert result["success"] == [1, 3]
        assert [f["item"] for f in result["failed"]] == [2, 4]
        assert all(isinstance(f["error"], str) for f in result["failed"])

    def test_success_and_failed_are_disjoint(self):
        def always_boom(item):
            raise ValueError("nope")

        result = execute_with_retry_per_item([1, 2, 3], always_boom, max_attempts=2)
        success_ids = set(id(r) for r in result["success"])
        failed_ids = set(id(f) for f in result["failed"])
        assert success_ids.isdisjoint(failed_ids)


class TestSummarizeResults:
    def test_computes_counts_and_rate(self):
        results = {
            "success": [1, 2, 3],
            "failed": [{"item": 4, "error": "boom"}],
        }
        summary = summarize_results(results)
        assert summary["success_count"] == 3
        assert summary["failed_count"] == 1
        assert summary["total"] == 4
        assert summary["success_rate"] == pytest.approx(0.75)

    def test_all_failed_yields_zero_rate(self):
        results = {
            "success": [],
            "failed": [{"item": 1, "error": "x"}, {"item": 2, "error": "y"}],
        }
        summary = summarize_results(results)
        assert summary["success_count"] == 0
        assert summary["failed_count"] == 2
        assert summary["total"] == 2
        assert summary["success_rate"] == 0.0

    def test_empty_case_yields_zero_rate(self):
        summary = summarize_results({"success": [], "failed": []})
        assert summary["success_count"] == 0
        assert summary["failed_count"] == 0
        assert summary["total"] == 0
        assert summary["success_rate"] == 0.0

    def test_round_trip_with_retry_executor(self):
        def volatile(item):
            if item == "bad":
                raise RuntimeError("failure")
            return item

        outcome = execute_with_retry_per_item(
            ["good", "bad", "fine"], volatile, max_attempts=2
        )
        summary = summarize_results(outcome)
        assert summary["success_count"] == 2
        assert summary["failed_count"] == 1
        assert summary["total"] == 3
        assert summary["success_rate"] == pytest.approx(2 / 3)
