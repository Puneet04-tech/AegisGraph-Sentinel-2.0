"""Bulk ingestion must not claim the configured fraud graph is loaded.

``state.graph_loaded`` means the transaction graph configured for this
deployment was loaded at startup, from Neo4j or from a GraphML artifact. It
drives ``_is_degraded_scoring_mode``, the graph detection paths and the health
report. Creating an empty in-memory container to ingest into is not the same
event, and conflating them switches scoring out of its fallback silently.
"""

import asyncio

import networkx as nx
import pytest

import src.api.main as api_main
from src.api.bulk_ingest_routes import BulkIngestionManager

NODE = {"id": "BULKFLAG1", "type": "Account", "properties": {}}


@pytest.fixture
def clean_graph_state(monkeypatch):
    monkeypatch.setattr(api_main.state, "transaction_graph", None, raising=False)
    monkeypatch.setattr(api_main.state, "graph_loaded", False, raising=False)
    yield


def _ingest(nodes, edges=()):
    manager = BulkIngestionManager()
    asyncio.run(manager._process_ingestion("task-under-test", list(nodes), list(edges)))


def test_ingestion_does_not_mark_the_graph_as_loaded(clean_graph_state):
    _ingest([NODE])

    assert api_main.state.graph_loaded is False, (
        "ingesting into a freshly created in-memory graph set graph_loaded, "
        "which claims the configured fraud graph was loaded at startup"
    )


def test_ingestion_still_creates_a_graph_and_writes_to_it(clean_graph_state):
    _ingest([NODE])

    assert api_main.state.transaction_graph is not None
    assert api_main.state.transaction_graph.has_node("BULKFLAG1")


def test_ingestion_does_not_leave_degraded_scoring_mode(clean_graph_state, monkeypatch):
    """With a model loaded but no graph, one ingested node must not flip this."""
    monkeypatch.setattr(api_main, "MODEL_AVAILABLE", True)

    assert api_main._is_degraded_scoring_mode() is True

    _ingest([NODE])

    assert api_main._is_degraded_scoring_mode() is True, (
        "a single ingested node turned degraded scoring mode off, so the "
        "amount band fallback stopped applying even though no fraud graph "
        "was ever loaded"
    )


def test_ingestion_leaves_a_real_loaded_graph_marked_as_loaded(monkeypatch):
    """The flag must survive ingestion when the graph genuinely was loaded."""
    monkeypatch.setattr(api_main.state, "transaction_graph", nx.DiGraph(), raising=False)
    monkeypatch.setattr(api_main.state, "graph_loaded", True, raising=False)

    _ingest([NODE])

    assert api_main.state.graph_loaded is True
    assert api_main.state.transaction_graph.has_node("BULKFLAG1")
