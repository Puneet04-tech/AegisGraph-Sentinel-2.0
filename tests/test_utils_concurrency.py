"""Unit tests for the concurrency utilities."""

import time

import pytest

from src.utils.concurrency import ThreadPoolExecutorContext, run_parallel, run_with_timeout


def double(x):
    return x * 2


def always_fail(x):
    raise ValueError(f"boom {x}")


class TestThreadPoolExecutorContext:
    def test_yields_executor_and_shuts_down_on_exit(self):
        with ThreadPoolExecutorContext() as executor:
            future = executor.submit(double, 21)
            assert future.result() == 42
        assert executor._shutdown

    def test_shuts_down_even_when_body_raises(self, monkeypatch):
        calls = {"shutdown": 0}
        monkeypatch.setattr(
            ThreadPoolExecutorContext,
            "__exit__",
            lambda self, et, exc, tb: calls.__setitem__("shutdown", calls["shutdown"] + 1),
        )
        with pytest.raises(RuntimeError):
            with ThreadPoolExecutorContext() as executor:
                executor.submit(double, 1)
                raise RuntimeError("body failed")
        assert calls["shutdown"] == 1

    def test_respects_max_workers(self):
        with ThreadPoolExecutorContext(max_workers=2) as executor:
            assert executor._max_workers == 2


class TestRunParallel:
    def test_maps_items_in_order(self):
        assert run_parallel(double, [1, 2, 3, 4]) == [2, 4, 6, 8]

    def test_handles_empty_input(self):
        assert run_parallel(double, []) == []

    def test_return_exceptions_collects_exceptions(self):
        results = run_parallel(always_fail, [1, 2], return_exceptions=True)
        assert isinstance(results[0], ValueError)
        assert isinstance(results[1], ValueError)
        assert str(results[0]) == "boom 1"

    def test_return_exceptions_mixes_values_and_errors(self):
        def maybe_fail(x):
            if x == 2:
                raise ValueError("bad")
            return x

        results = run_parallel(maybe_fail, [1, 2, 3], return_exceptions=True)
        assert results[0] == 1
        assert isinstance(results[1], ValueError)
        assert results[2] == 3

    def test_raises_exception_when_not_collecting(self):
        with pytest.raises(ValueError, match="boom 1"):
            run_parallel(always_fail, [1])

    def test_max_workers_respected(self, monkeypatch):
        seen = []
        original = ThreadPoolExecutorContext.__enter__

        def patched_enter(self):
            seen.append(self.executor._max_workers)
            return original(self)

        monkeypatch.setattr(ThreadPoolExecutorContext, "__enter__", patched_enter)
        run_parallel(double, [1, 2, 3], max_workers=1)
        assert seen == [1]


class TestRunWithTimeout:
    def test_returns_result_when_fast(self):
        assert run_with_timeout(double, 1.0, 4) == 8

    def test_raises_timeout_when_slow(self):
        with pytest.raises(TimeoutError):
            run_with_timeout(lambda: time.sleep(0.3), 0.05)

    def test_propagates_exception_from_function(self):
        with pytest.raises(ValueError, match="boom 1"):
            run_with_timeout(always_fail, 1.0, 1)
