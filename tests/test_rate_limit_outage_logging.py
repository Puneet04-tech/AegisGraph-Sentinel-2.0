"""A rate limiter outage must not be reported once per request.

check_rate_limit falls back to a process-local token bucket when its backend is
unreachable, so throttling still applies during an outage. It logged that
decision at WARNING with a full traceback every time, so an outage produced a
stack trace on every request and buried the incident in its own output.
"""

import logging

import pytest

import src.security.rate_limit as rate_limit_mod


@pytest.fixture(autouse=True)
def _clean_outage_state(monkeypatch):
    monkeypatch.setattr(
        rate_limit_mod,
        "get_redis_client",
        lambda redis_url=None: (_ for _ in ()).throw(RuntimeError("redis down")),
    )
    _reset()
    yield
    _reset()


def _reset():
    """Clear the outage throttle and local fallback buckets if present."""
    getattr(rate_limit_mod, "_reset_outage_log_state", lambda: None)()
    getattr(rate_limit_mod, "_reset_local_buckets", lambda: None)()


def _call(identity="caller"):
    return rate_limit_mod.check_rate_limit(identity, limit=5, burst=5, window_seconds=60)


def test_the_request_is_still_allowed_when_the_backend_is_down(caplog):
    """Local fallback must keep serving within the configured budget."""
    with caplog.at_level(logging.WARNING):
        decision = _call()

    assert decision.allowed is True
    assert decision.retry_after_seconds == 0


def test_the_first_outage_is_reported_with_a_traceback(caplog):
    with caplog.at_level(logging.WARNING):
        _call()

    records = [r for r in caplog.records if "Rate limiter unavailable" in r.getMessage()]
    assert len(records) == 1
    assert records[0].exc_info is not None, "the first report should carry a traceback"


def test_further_requests_during_one_outage_are_not_reported(caplog):
    with caplog.at_level(logging.WARNING):
        for _ in range(25):
            _call()

    reports = [
        r for r in caplog.records if "Rate limiter" in r.getMessage()
    ]

    assert len(reports) == 1, (
        f"25 requests during a single outage produced {len(reports)} log records: "
        f"{[r.getMessage()[:60] for r in reports]}. An outage affects every "
        "request, so reporting each one buries the incident."
    )


def test_no_traceback_is_emitted_per_request(caplog):
    with caplog.at_level(logging.WARNING):
        for _ in range(10):
            _call()

    with_traceback = [r for r in caplog.records if r.exc_info is not None]

    assert len(with_traceback) <= 1, (
        f"{len(with_traceback)} stack traces were logged for 10 requests"
    )


def test_a_continuing_outage_is_summarised_after_the_interval(caplog, monkeypatch):
    monkeypatch.setattr(rate_limit_mod, "_OUTAGE_LOG_INTERVAL_SECONDS", 0.0)

    with caplog.at_level(logging.WARNING):
        _call()
        for _ in range(4):
            _call()

    messages = [r.getMessage() for r in caplog.records if "Rate limiter" in r.getMessage()]

    assert any("still unavailable" in m for m in messages), (
        f"a continuing outage was never re-reported: {messages}"
    )


def test_recovery_is_reported_and_resets_the_throttle(caplog, monkeypatch):
    with caplog.at_level(logging.WARNING):
        _call()

        class _Redis:
            def eval(self, *args, **kwargs):
                return [1, 0, 4.0]

        monkeypatch.setattr(rate_limit_mod, "get_redis_client", lambda redis_url=None: _Redis())
        _call()

        monkeypatch.setattr(
            rate_limit_mod,
            "get_redis_client",
            lambda redis_url=None: (_ for _ in ()).throw(RuntimeError("down again")),
        )
        _call()

    messages = [r.getMessage() for r in caplog.records if "Rate limiter" in r.getMessage()]

    assert any("available again" in m for m in messages), (
        f"recovery was never reported: {messages}"
    )
    outage_reports = [m for m in messages if "Rate limiter unavailable" in m or "still unavailable" in m]
    assert len(outage_reports) == 2, (
        "a second outage should be reported afresh rather than stay suppressed: "
        f"{messages}"
    )
