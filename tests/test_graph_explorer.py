"""Dedicated unit tests for src/threat_hunting/graph_explorer.py.

``GraphIntelligenceExplorer.discover_attack_paths`` walks relationship
graphs with a bounded DFS and records attack paths that terminate at
entities whose cached threat score exceeds the 0.6 threshold.  These tests
cover path reconstruction, the depth cap, cycle safety and the score
threshold boundary.
"""

from __future__ import annotations

import pytest

from src.threat_hunting.graph_explorer import GraphIntelligenceExplorer
from src.threat_hunting.models import AttackPath, ThreatScore
from src.threat_hunting.store import ThreatHuntingStore


class FakeStore:
    """Minimal stand-in for ThreatHuntingStore returning canned scores."""

    def __init__(self, scores: dict[str, float] | None = None):
        self._scores = dict(scores or {})

    def get_threat_score(self, entity_id: str):
        score = self._scores.get(entity_id)
        if score is None:
            return None
        return ThreatScore(entity_id=entity_id, score=score)


@pytest.fixture
def make_explorer():
    def _build(scores):
        return GraphIntelligenceExplorer(store=FakeStore(scores))

    return _build


def _rel(src, dst, rtype="link"):
    return {"from_id": src, "to_id": dst, "type": rtype}


# ---------------------------------------------------------------------------
# No / non-threatening graphs
# ---------------------------------------------------------------------------


def test_no_relationships_yields_no_paths(make_explorer):
    explorer = make_explorer({})
    assert explorer.discover_attack_paths("start", []) == []


def test_low_score_target_is_not_recorded(make_explorer):
    explorer = make_explorer({"target": 0.5})
    rels = [_rel("start", "target")]
    assert explorer.discover_attack_paths("start", rels) == []


def test_score_exactly_at_threshold_is_not_a_threat(make_explorer):
    # The check is strictly > 0.6.
    explorer = make_explorer({"target": 0.6})
    rels = [_rel("start", "target")]
    assert explorer.discover_attack_paths("start", rels) == []


# ---------------------------------------------------------------------------
# Path reconstruction
# ---------------------------------------------------------------------------


def test_short_path_to_high_risk_target(make_explorer):
    explorer = make_explorer({"target": 0.9})
    rels = [_rel("start", "target")]
    paths = explorer.discover_attack_paths("start", rels)
    assert len(paths) == 1
    assert isinstance(paths[0], AttackPath)
    assert [n["id"] for n in paths[0].nodes] == ["start", "target"]
    assert paths[0].edges == [{"from": "start", "to": "target", "type": "link"}]
    assert paths[0].risk_score == pytest.approx(0.9)
    assert "start" in paths[0].description
    assert "target" in paths[0].description


def test_multi_hop_path_to_high_risk_target(make_explorer):
    explorer = make_explorer({"target": 0.85})
    rels = [_rel("start", "mid"), _rel("mid", "target")]
    paths = explorer.discover_attack_paths("start", rels)
    assert len(paths) == 1
    p = paths[0]
    assert [n["id"] for n in p.nodes] == ["start", "mid", "target"]
    assert len(p.edges) == 2
    assert p.risk_score == pytest.approx(0.85)


def test_relationship_type_is_preserved_in_edges(make_explorer):
    explorer = make_explorer({"t": 0.9})
    rels = [_rel("s", "t", "owns")]
    paths = explorer.discover_attack_paths("s", rels)
    assert paths[0].edges[0]["type"] == "owns"


# ---------------------------------------------------------------------------
# Traversal constraints
# ---------------------------------------------------------------------------


def test_max_depth_caps_traversal_before_target(make_explorer):
    explorer = make_explorer({"target": 0.9})
    rels = [_rel("s", "a"), _rel("a", "b"), _rel("b", "c"), _rel("c", "target")]
    # default max_depth=3: target sits at depth 5 -> unreachable
    assert explorer.discover_attack_paths("s", rels) == []
    # raising the cap exposes the path
    paths = explorer.discover_attack_paths("s", rels, max_depth=5)
    assert len(paths) == 1
    assert [n["id"] for n in paths[0].nodes] == ["s", "a", "b", "c", "target"]


def test_depth_one_rejects_start_itself_as_target(make_explorer):
    # If the start node is flagged, the path length is 1 which fails the
    # `len(current_path_nodes) > 1` guard -> no path recorded.
    explorer = make_explorer({"start": 0.9})
    rels = [_rel("start", "mid")]
    assert explorer.discover_attack_paths("start", rels) == []


# ---------------------------------------------------------------------------
# Cycle safety
# ---------------------------------------------------------------------------


def test_cyclic_graph_terminates_and_records_target_once(make_explorer):
    explorer = make_explorer({"target": 0.9})
    # target -> a forms a cycle; DFS must terminate and record exactly one path.
    rels = [
        _rel("start", "a"),
        _rel("a", "target"),
        _rel("target", "a"),
    ]
    paths = explorer.discover_attack_paths("start", rels)
    assert len(paths) == 1
    assert [n["id"] for n in paths[0].nodes] == ["start", "a", "target"]


def test_bidirectional_cycle_does_not_loop_forever(make_explorer):
    explorer = make_explorer({"a": 0.9})
    rels = [_rel("start", "a"), _rel("a", "start")]
    # start is reached again via a, but already visited -> terminates.
    paths = explorer.discover_attack_paths("start", rels, max_depth=10)
    # Path [start, a] has length 2>1 and 'a' is a threat -> exactly one path.
    assert len(paths) == 1
    assert [n["id"] for n in paths[0].nodes] == ["start", "a"]


# ---------------------------------------------------------------------------
# Multiple targets
# ---------------------------------------------------------------------------


def test_multiple_targets_yield_multiple_paths(make_explorer):
    explorer = make_explorer({"t1": 0.7, "t2": 0.9})
    rels = [_rel("start", "t1"), _rel("start", "t2")]
    paths = explorer.discover_attack_paths("start", rels)
    assert len(paths) == 2
    recorded = {p.nodes[-1]["id"] for p in paths}
    assert recorded == {"t1", "t2"}
