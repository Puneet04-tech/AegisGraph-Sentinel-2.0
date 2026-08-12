"""Honeypot trace_network must walk depth-2 fraud networks (Issue #3510).

``trace_network`` documented depth-2 tracing but only collected the mule's
direct predecessors and successors, silently omitting second-order members of
the fraud network. These tests pin the two-level breadth-first expansion and
the single-count-per-honeypot dismantle guard.
"""

import networkx as nx
import pytest

from src.features.honeypot_escrow import HoneypotEscrowManager, HoneypotStatus


@pytest.fixture
def manager() -> HoneypotEscrowManager:
    return HoneypotEscrowManager()


@pytest.fixture
def active_honeypot(manager):
    return manager.activate_honeypot(
        transaction_id="TXN-D2",
        source_account="SRC",
        target_account="MULE",
        amount=1000.0,
        currency="USD",
        risk_score=0.95,
        fraud_indicators=["mule_to_mule"],
    )


def _depth2_chain():
    """A -> MULE -> B -> C: C is reachable only through an intermediate."""
    G = nx.DiGraph()
    G.add_nodes_from(["A", "MULE", "B", "C"])
    G.add_edges_from([("A", "MULE"), ("MULE", "B"), ("B", "C")])
    return G


class TestTraceNetworkDepthTwo:
    def test_second_order_account_is_included(self, manager, active_honeypot):
        members = manager.trace_network(active_honeypot.honeypot_id, _depth2_chain())
        # A (predecessor), B (successor) and C (depth-2) are all discovered.
        assert set(members) == {"A", "MULE", "B", "C"}
        assert "C" in members
        assert active_honeypot.status == HoneypotStatus.NETWORK_TRACED

    def test_repeat_trace_does_not_inflate_dismantled_count(
        self, manager, active_honeypot
    ):
        G = nx.DiGraph()
        G.add_nodes_from(["MULE", "B", "C", "D", "E", "F", "G", "H"])
        G.add_edges_from(
            [
                ("MULE", "B"),
                ("MULE", "C"),
                ("B", "D"),
                ("B", "E"),
                ("C", "F"),
                ("C", "G"),
                ("F", "H"),
            ]
        )
        before = manager.stats["total_networks_dismantled"]

        first = manager.trace_network(active_honeypot.honeypot_id, G)
        manager.trace_network(active_honeypot.honeypot_id, G)

        assert len(first) > 5
        assert manager.stats["total_networks_dismantled"] == before + 1
