"""Unit tests for the retry utility with exponential backoff."""

import asyncio
import time

import pytest

from src.utils.retry import RetryPolicy, retry, retry_sync


class TestRetryPolicyValidation:
    def test_rejects_non_positive_attempts(self):
        with pytest.raises(ValueError):
            RetryPolicy(max_attempts=0)

    def test_rejects_negative_delay(self):
        with pytest.raises(ValueError):
            RetryPolicy(base_delay=-1)

    def test_rejects_non_positive_backoff(self):
        with pytest.raises(ValueError):
            RetryPolicy(backoff_factor=0)

    def test_defaults(self):
        policy = RetryPolicy()
        assert policy.max_attempts == 3
        assert policy.retry_on == (Exception,)


class TestRetrySucceedsOnRetry:
    def test_succeeds_after_failures(self):
        calls = {"n": 0}

        @retry(max_attempts=4, base_delay=0)
        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise ValueError("transient")
            return "ok"

        assert flaky() == "ok"
        assert calls["n"] == 3

    def test_first_attempt_success(self):
        calls = {"n": 0}

        @retry(max_attempts=3, base_delay=0)
        def good():
            calls["n"] += 1
            return 42

        assert good() == 42
        assert calls["n"] == 1


class TestRetryExhausts:
    def test_raises_after_all_attempts(self):
        calls = {"n": 0}

        @retry(max_attempts=3, base_delay=0)
        def always_fails():
            calls["n"] += 1
            raise ValueError("boom")

        with pytest.raises(ValueError):
            always_fails()
        assert calls["n"] == 3

    def test_raises_last_error(self):
        @retry(max_attempts=2, base_delay=0)
        def fail():
            raise RuntimeError("last")

        with pytest.raises(RuntimeError):
            fail()


class TestRetryOnSpecificExceptions:
    def test_only_retries_listed_exceptions(self):
        calls = {"n": 0}

        @retry(max_attempts=3, base_delay=0, retry_on=(ValueError,))
        def raises_key_error():
            calls["n"] += 1
            raise KeyError("no retry")

        with pytest.raises(KeyError):
            raises_key_error()
        assert calls["n"] == 1

    def test_retries_matching_exception(self):
        calls = {"n": 0}

        @retry(max_attempts=3, base_delay=0, retry_on=(ValueError,))
        def raises_value_error():
            calls["n"] += 1
            if calls["n"] < 2:
                raise ValueError("retry me")
            return "recovered"

        assert raises_value_error() == "recovered"
        assert calls["n"] == 2


class TestRetryBackoffAndJitter:
    def test_jitter_disabled_uses_deterministic_delays(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr("src.utils.retry._sleep", lambda d: sleeps.append(d))
        calls = {"n": 0}

        @retry(max_attempts=4, base_delay=0.1, backoff_factor=2.0, jitter=False)
        def flaky():
            calls["n"] += 1
            raise ValueError("retry")

        with pytest.raises(ValueError):
            flaky()
        assert sleeps == [0.1, 0.2, 0.4]

    def test_jitter_produces_delays_within_range(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr("src.utils.retry._sleep", lambda d: sleeps.append(d))
        calls = {"n": 0}

        @retry(max_attempts=4, base_delay=0.1, backoff_factor=2.0, jitter=True)
        def flaky():
            calls["n"] += 1
            raise ValueError("retry")

        with pytest.raises(ValueError):
            flaky()
        assert len(sleeps) == 3
        for delay in sleeps:
            assert 0.0 <= delay <= 0.4

    def test_max_delay_caps_backoff(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr("src.utils.retry._sleep", lambda d: sleeps.append(d))
        calls = {"n": 0}

        @retry(max_attempts=4, base_delay=1.0, backoff_factor=10.0, max_delay=2.0, jitter=False)
        def flaky():
            calls["n"] += 1
            raise ValueError("retry")

        with pytest.raises(ValueError):
            flaky()
        assert sleeps == [1.0, 2.0, 2.0]


class TestRetryCallback:
    def test_on_retry_receives_exception_and_attempt(self):
        seen = []

        def on_retry(exc, attempt):
            seen.append((type(exc).__name__, attempt))

        calls = {"n": 0}

        @retry(max_attempts=3, base_delay=0, on_retry=on_retry)
        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise ValueError("retry")
            return "done"

        assert flaky() == "done"
        assert seen == [("ValueError", 1), ("ValueError", 2)]


class TestRetryAsync:
    def test_async_retry_succeeds(self):
        calls = {"n": 0}

        @retry(max_attempts=4, base_delay=0)
        async def flaky_async():
            calls["n"] += 1
            if calls["n"] < 3:
                raise ValueError("transient")
            return "async-ok"

        assert asyncio.run(flaky_async()) == "async-ok"
        assert calls["n"] == 3

    def test_async_retry_exhausts(self):
        calls = {"n": 0}

        @retry(max_attempts=2, base_delay=0)
        async def flaky_async():
            calls["n"] += 1
            raise ValueError("boom")

        with pytest.raises(ValueError):
            asyncio.run(flaky_async())
        assert calls["n"] == 2


class TestRetryFormsAndHelpers:
    def test_retry_without_parentheses(self):
        calls = {"n": 0}

        @retry
        def flaky():
            calls["n"] += 1
            if calls["n"] < 2:
                raise ValueError("retry")
            return "bare"

        assert flaky() == "bare"
        assert calls["n"] == 2

    def test_retry_sync_helper(self):
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 2:
                raise ValueError("retry")
            return "helper"

        policy = RetryPolicy(max_attempts=3, base_delay=0)
        assert retry_sync(flaky, policy) == "helper"
        assert calls["n"] == 2

    def test_kwargs_construct_policy(self):
        calls = {"n": 0}

        @retry(max_attempts=5, base_delay=0, jitter=False)
        def flaky():
            calls["n"] += 1
            if calls["n"] < 4:
                raise ValueError("retry")
            return "kwargs"

        assert flaky() == "kwargs"
        assert calls["n"] == 4
