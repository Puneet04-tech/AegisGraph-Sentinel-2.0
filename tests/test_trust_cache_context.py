"""Tests that trust score cache keys include risk-relevant context."""

from src.zero_trust.models import EvaluationContext, TrustScore
from src.zero_trust.store import ZeroTrustStore
from src.zero_trust.trust_engine import TrustEngine


class TestTrustCacheContext:
    def test_cache_key_differs_by_ip(self):
        store = ZeroTrustStore()
        key_a = store._trust_key("user-1", "device-1", ip_address="1.1.1.1")
        key_b = store._trust_key("user-1", "device-1", ip_address="8.8.8.8")
        assert key_a != key_b

    def test_cache_key_differs_by_location(self):
        store = ZeroTrustStore()
        key_a = store._trust_key(
            "user-1", "device-1", location={"country": "US", "city": "NYC"}
        )
        key_b = store._trust_key(
            "user-1", "device-1", location={"country": "RU", "city": "MSK"}
        )
        assert key_a != key_b

    def test_store_miss_when_ip_changes(self):
        store = ZeroTrustStore()
        score = TrustScore(score=0.9)
        store.set_trust_score(
            "user-1",
            "device-1",
            score,
            ip_address="1.1.1.1",
            location={"country": "US"},
        )
        hit = store.get_trust_score(
            "user-1",
            "device-1",
            ip_address="1.1.1.1",
            location={"country": "US"},
        )
        miss = store.get_trust_score(
            "user-1",
            "device-1",
            ip_address="203.0.113.50",
            location={"country": "US"},
        )
        assert hit is not None
        assert hit.score == 0.9
        assert miss is None

    def test_evaluate_trust_does_not_reuse_score_across_ips(self):
        store = ZeroTrustStore()
        engine = TrustEngine(store=store)

        clean = engine.evaluate_trust(
            EvaluationContext(user_id="user-1", device_id="device-1", ip_address="8.8.8.8"),
            cached=True,
        )
        # Same user/device, elevated risk IP (TOR-like range used elsewhere)
        elevated = engine.evaluate_trust(
            EvaluationContext(
                user_id="user-1",
                device_id="device-1",
                ip_address="185.220.101.5",
            ),
            cached=True,
        )
        assert clean.factors.tor_detected is False
        assert elevated.factors.tor_detected is True
        assert elevated.score != clean.score or elevated.factors.tor_detected != clean.factors.tor_detected
