from __future__ import annotations

import math
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.security import rate_limit as rate_limit_mod


@dataclass
class _Decision:
    allowed: bool
    retry_after_seconds: int
    remaining_tokens: float


class FakeRedis:
    def __init__(self):
        self.state = {}

    def eval(self, script, numkeys, key, now, refill_rate, capacity, ttl_seconds):
        now = float(now)
        refill_rate = float(refill_rate)
        capacity = float(capacity)
        tokens, ts = self.state.get(key, (capacity, now))
        elapsed = max(0.0, now - ts)
        tokens = min(capacity, tokens + (elapsed * refill_rate))
        if tokens >= 1:
            tokens -= 1
            allowed = 1
            retry_after = 0
        else:
            allowed = 0
            retry_after = max(1, math.ceil((1 - tokens) / refill_rate))
        self.state[key] = (tokens, now)
        return [allowed, retry_after, tokens]


@pytest.fixture
def fake_settings():
    class _Settings:
        class api:
            rate_limit = "5/minute"
            rate_limit_burst = 5
            rate_limit_window_seconds = 60

        class innovations:
            redis_url = "redis://unused"

    return _Settings()


def test_check_rate_limit_allows_initial_requests(monkeypatch, fake_settings):
    fake_redis = FakeRedis()
    monkeypatch.setattr(rate_limit_mod, "get_settings", lambda: fake_settings)
    monkeypatch.setattr(rate_limit_mod, "get_redis_client", lambda redis_url=None: fake_redis)

    decision = rate_limit_mod.check_rate_limit("api-key-1", scope="api_key")
    assert decision.allowed is True
    assert decision.retry_after_seconds == 0
    assert decision.remaining_tokens == 4


def test_check_rate_limit_exceeds_limit_and_sets_retry_after(monkeypatch, fake_settings):
    fake_redis = FakeRedis()
    monkeypatch.setattr(rate_limit_mod, "get_settings", lambda: fake_settings)
    monkeypatch.setattr(rate_limit_mod, "get_redis_client", lambda redis_url=None: fake_redis)

    for _ in range(5):
        assert rate_limit_mod.check_rate_limit("api-key-2").allowed is True

    decision = rate_limit_mod.check_rate_limit("api-key-2")
    assert decision.allowed is False
    assert decision.retry_after_seconds >= 1


def test_check_rate_limit_isolated_by_identity(monkeypatch, fake_settings):
    fake_redis = FakeRedis()
    monkeypatch.setattr(rate_limit_mod, "get_settings", lambda: fake_settings)
    monkeypatch.setattr(rate_limit_mod, "get_redis_client", lambda redis_url=None: fake_redis)

    for _ in range(5):
        rate_limit_mod.check_rate_limit("api-key-a")

    other = rate_limit_mod.check_rate_limit("api-key-b")
    assert other.allowed is True


def test_check_rate_limit_fails_open_when_redis_unavailable(monkeypatch, fake_settings):
    monkeypatch.setattr(rate_limit_mod, "get_settings", lambda: fake_settings)
    monkeypatch.setattr(rate_limit_mod, "get_redis_client", lambda redis_url=None: (_ for _ in ()).throw(RuntimeError("redis down")))

    decision = rate_limit_mod.check_rate_limit("api-key-3")
    assert decision.allowed is True
    assert decision.retry_after_seconds == 0


def test_rate_limit_middleware_returns_429_and_retry_after(monkeypatch):
    monkeypatch.setattr(
        "src.api.main.check_rate_limit",
        lambda identity, **kwargs: _Decision(False, 17, 0.0),
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/model/info")

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "17"
    assert response.json()["error"]["details"]["retry_after_seconds"] == 17


def test_rate_limit_middleware_allows_normal_request(monkeypatch):
    monkeypatch.setattr(
        "src.api.main.check_rate_limit",
        lambda identity, **kwargs: _Decision(True, 0, 99.0),
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/model/info")

    assert response.status_code != 429
