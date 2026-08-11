"""
Regression tests for HoneypotEscrowManager arrest recording and network tracing.

Covers two fixed defects:
1. ``record_arrest`` crashed with ``KeyError`` when ``arrest_details`` lacked an
   ``arrest_time`` (or carried a malformed one) *after* statistics had already
   been mutated, leaving the system in an inconsistent state: the arrest counter
   was incremented while the honeypot remained registered as active.
2. ``trace_network`` incremented ``total_networks_dismantled`` on every call,
   so tracing the same honeypot twice inflated the metric.
"""

import networkx as nx
import pytest

from src.features.honeypot_escrow import HoneypotEscrowManager, HoneypotStatus


@pytest.fixture
def manager():
    return HoneypotEscrowManager()


@pytest.fixture
def active_honeypot(manager):
    return manager.activate_honeypot(
        transaction_id="TXN_1",
        source_account="SRC_A",
        target_account="MULE_1",
        amount=1000.0,
        currency="USD",
        risk_score=0.95,
        fraud_indicators=["mule_to_mule"],
    )


def _withdraw(manager, account="MULE_1", amount=500.0):
    return manager.record_withdrawal_attempt(
        account, "ATM", amount, {"address": "122 Main St"}
    )


class TestRecordArrestRobustness:
    """record_arrest must never leave stats mutated on failure."""

    def test_arrest_without_arrest_time_does_not_crash(self, manager, active_honeypot):
        _withdraw(manager)
        arrests_before = manager.stats["total_arrests"]

        result = manager.record_arrest(active_honeypot.honeypot_id, {})

        assert result is True
        assert manager.stats["total_arrests"] == arrests_before + 1
        # The honeypot is finalized: removed from active tracking.
        assert active_honeypot.honeypot_id not in manager.active_honeypots
        assert active_honeypot.honeypot_id not in manager._active_honeypots_by_account.values()

    def test_arrest_with_malformed_arrest_time_does_not_crash(self, manager, active_honeypot):
        _withdraw(manager)
        result = manager.record_arrest(
            active_honeypot.honeypot_id, {"arrest_time": "not-a-timestamp"}
        )
        assert result is True
        assert active_honeypot.honeypot_id not in manager.active_honeypots

    def test_arrest_with_valid_time_updates_average(self, manager, active_honeypot):
        _withdraw(manager)
        # Simulate a 30-minute response by placing withdrawal 30 min before arrest.
        from datetime import datetime, timedelta
        attempt_time = datetime.now() - timedelta(minutes=30)
        active_honeypot.withdrawal_attempts[0]["timestamp"] = attempt_time.isoformat()
        arrest_time = (attempt_time + timedelta(minutes=30)).isoformat()

        old_avg = manager.stats["average_response_time_minutes"]
        old_arrests = manager.stats["total_arrests"]
        result = manager.record_arrest(
            active_honeypot.honeypot_id, {"arrest_time": arrest_time}
        )
        assert result is True
        expected = ((old_avg * old_arrests) + 30.0) / (old_arrests + 1)
        assert manager.stats["average_response_time_minutes"] == pytest.approx(expected)

    def test_arrest_without_withdrawal_still_finalizes(self, manager, active_honeypot):
        result = manager.record_arrest(
            active_honeypot.honeypot_id, {"arrest_time": "2026-07-31T12:00:00"}
        )
        assert result is True
        assert active_honeypot.honeypot_id not in manager.active_honeypots
        assert active_honeypot.honeypot_id in [h.honeypot_id for h in manager.honeypot_history]

    def test_arrest_updates_daily_stats(self, manager, active_honeypot):
        _withdraw(manager)
        recovered_before = manager.daily_stats["recovered"]
        manager.record_arrest(active_honeypot.honeypot_id, {})
        assert manager.daily_stats["arrests"] == 1
        assert manager.daily_stats["recovered"] == recovered_before + 1000.0

    def test_arrest_records_recovered_amount(self, manager, active_honeypot):
        _withdraw(manager)
        before = manager.stats["total_recovered"]
        manager.record_arrest(active_honeypot.honeypot_id, {})
        assert manager.stats["total_recovered"] == before + 1000.0

    def test_arrest_unknown_honeypot_returns_false(self, manager):
        assert manager.record_arrest("HP_MISSING", {}) is False

    def test_arrest_sets_status(self, manager, active_honeypot):
        _withdraw(manager)
        manager.record_arrest(active_honeypot.honeypot_id, {})
        assert active_honeypot.status == HoneypotStatus.ARRESTED


class TestTraceNetworkDismantleCounting:
    """total_networks_dismantled must be incremented at most once per honeypot."""

    def _big_graph(self):
        G = nx.DiGraph()
        nodes = ["MULE_1", "B", "C", "D", "E", "F", "G"]
        G.add_nodes_from(nodes)
        G.add_edges_from(
            [
                ("B", "MULE_1"),
                ("C", "MULE_1"),
                ("MULE_1", "D"),
                ("MULE_1", "E"),
                ("MULE_1", "F"),
                ("MULE_1", "G"),
            ]
        )
        return G

    def test_first_trace_counts_dismantle(self, manager, active_honeypot):
        before = manager.stats["total_networks_dismantled"]
        members = manager.trace_network(active_honeypot.honeypot_id, self._big_graph())
        assert len(members) == 7
        assert manager.stats["total_networks_dismantled"] == before + 1

    def test_repeat_trace_does_not_double_count(self, manager, active_honeypot):
        before = manager.stats["total_networks_dismantled"]
        manager.trace_network(active_honeypot.honeypot_id, self._big_graph())
        manager.trace_network(active_honeypot.honeypot_id, self._big_graph())
        manager.trace_network(active_honeypot.honeypot_id, self._big_graph())
        assert manager.stats["total_networks_dismantled"] == before + 1

    def test_small_network_not_counted(self, manager, active_honeypot):
        G = nx.DiGraph()
        G.add_nodes_from(["MULE_1", "B", "C"])
        G.add_edges_from([("B", "MULE_1"), ("MULE_1", "C")])
        before = manager.stats["total_networks_dismantled"]
        members = manager.trace_network(active_honeypot.honeypot_id, G)
        assert len(members) == 3
        assert manager.stats["total_networks_dismantled"] == before

    def test_small_then_large_network_counts_once(self, manager, active_honeypot):
        small = nx.DiGraph()
        small.add_nodes_from(["MULE_1", "B", "C"])
        small.add_edges_from([("B", "MULE_1"), ("MULE_1", "C")])
        before = manager.stats["total_networks_dismantled"]
        manager.trace_network(active_honeypot.honeypot_id, small)
        manager.trace_network(active_honeypot.honeypot_id, self._big_graph())
        assert manager.stats["total_networks_dismantled"] == before + 1

    def test_different_honeypots_count_separately(self, manager):
        hp1 = manager.activate_honeypot(
            "TXN_1", "SRC_A", "MULE_1", 100.0, "USD", 0.95, ["mule_to_mule"]
        )
        hp2 = manager.activate_honeypot(
            "TXN_2", "SRC_B", "MULE_2", 200.0, "USD", 0.95, ["mule_to_mule"]
        )
        G = nx.DiGraph()
        nodes = ["MULE_1", "B", "C", "D", "E", "F", "G"]
        G.add_nodes_from(nodes)
        G.add_edges_from(
            [
                ("B", "MULE_1"),
                ("C", "MULE_1"),
                ("MULE_1", "D"),
                ("MULE_1", "E"),
                ("MULE_1", "F"),
                ("MULE_1", "G"),
            ]
        )
        before = manager.stats["total_networks_dismantled"]
        # MULE_2 is a fresh node in an unrelated subgraph with 6 neighbors.
        for i in range(1, 7):
            G.add_edge("MULE_2", f"X{i}")
        manager.trace_network(hp1.honeypot_id, G)
        manager.trace_network(hp2.honeypot_id, G)
        assert manager.stats["total_networks_dismantled"] == before + 2

    def test_trace_unknown_honeypot_returns_empty(self, manager):
        assert manager.trace_network("HP_MISSING", nx.DiGraph()) == []

    def test_trace_sets_network_traced_status(self, manager, active_honeypot):
        manager.trace_network(active_honeypot.honeypot_id, self._big_graph())
        assert active_honeypot.status == HoneypotStatus.NETWORK_TRACED


class TestWithdrawalIntegration:
    """Withdrawal, arrest, auto-release, and stats integration."""

    def test_alert_returned_on_withdrawal(self, manager, active_honeypot):
        alert = _withdraw(manager)
        assert alert is not None
        assert alert["honeypot_id"] == active_honeypot.honeypot_id
        assert alert["mule_account"] == "MULE_1"

    def test_withdrawal_on_released_honeypot_returns_none(self, manager, active_honeypot):
        active_honeypot.released = True
        assert _withdraw(manager) is None

    def test_withdrawal_unknown_account_returns_none(self, manager):
        assert _withdraw(manager, account="REGULAR_ACCT") is None

    def test_auto_release_after_timeout(self, manager, active_honeypot):
        active_honeypot.auto_release_time = active_honeypot.activation_time
        manager.check_auto_release()
        assert active_honeypot.released is True
        assert active_honeypot.status == HoneypotStatus.RELEASED
        assert active_honeypot.honeypot_id not in manager.active_honeypots
        assert manager.stats["total_false_positives"] == 1

    def test_auto_release_before_timeout_skipped(self, manager, active_honeypot):
        manager.check_auto_release()
        assert active_honeypot.released is False
        assert active_honeypot.honeypot_id in manager.active_honeypots

    def test_arrest_metrics_report(self, manager, active_honeypot):
        _withdraw(manager)
        manager.record_arrest(active_honeypot.honeypot_id, {})
        stats = manager.get_statistics()
        assert stats["total_arrests"] == 1
        assert stats["total_recovered"] == 1000.0
        assert stats["active_honeypots"] == 0


class TestHoneypotRouteDependencies:
    """Verify Honeypot API routes load without missing dependency NameErrors."""

    def test_honeypot_routes_import_cleanly(self):
        from src.api.main import app

        route_paths = [getattr(route, "path", None) for route in app.routes]
        assert "/api/v1/honeypot/active" in route_paths
        assert "/api/v1/honeypot/stats" in route_paths

