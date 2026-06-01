"""
Evaluator: runs an attack over many graphs and reports aggregate metrics.

Currently builds synthetic graphs matching example_training.py's format. Future
work: accept any DataLoader so we can evaluate against real test sets.
"""
from __future__ import annotations
import statistics
from dataclasses import dataclass
from typing import Callable, List
import torch

from .base import BaseAttack, Graph


@dataclass
class EvaluationResult:
    """Aggregate metrics from running one attack over N graphs."""
    attack_name: str
    budget: float
    n_graphs: int
    clean_mean: float
    clean_std: float
    attacked_mean: float
    attacked_std: float
    delta_mean: float
    delta_std: float
    flip_rate: float
    threshold: float


def build_synthetic_graph(num_nodes=30, num_edges=60, feature_dim=32, seed=0) -> Graph:
    """One synthetic graph matching example_training.py's format."""
    gen = torch.Generator().manual_seed(seed)
    return {
        "x": torch.randn(num_nodes, feature_dim, generator=gen),
        "edge_index": torch.randint(0, num_nodes, (2, num_edges), generator=gen),
        "node_type": torch.randint(0, 5, (num_nodes,), generator=gen),
        "edge_type": torch.randint(0, 4, (num_edges,), generator=gen),
        "edge_timestamp": torch.rand(num_edges, generator=gen) * 86400,
    }


def predict(model: torch.nn.Module, graph: Graph) -> float:
    """Forward pass on one graph; return risk as a Python float."""
    with torch.no_grad():
        out = model(
            x=graph["x"],
            edge_index=graph["edge_index"],
            node_type=graph["node_type"],
            edge_type=graph["edge_type"],
            edge_timestamp=graph["edge_timestamp"],
        )
    return float(out["risk"].item())


def evaluate_attack(
    model: torch.nn.Module,
    attack: BaseAttack,
    n_graphs: int = 50,
    threshold: float = 0.5,
    graph_builder: Callable[..., Graph] = build_synthetic_graph,
    seed_offset: int = 1000,
) -> EvaluationResult:
    """Run one attack over n_graphs graphs; return aggregate metrics.

    Args:
        model: the model to attack
        attack: an instantiated BaseAttack subclass
        n_graphs: number of graphs to evaluate
        threshold: decision threshold for flip-rate calculation
        graph_builder: function returning a Graph dict given a seed kwarg
        seed_offset: added to graph seed for attack seed, so perturbations vary
        per graph while staying reproducible
    """
    clean_risks: List[float] = []
    attacked_risks: List[float] = []
    deltas: List[float] = []
    flips = 0

    model.eval()

    for i in range(n_graphs):
        g = graph_builder(seed=i)
        attack.config.seed = i + seed_offset
        g_attacked = attack.perturb(g)

        clean = predict(model, g)
        attacked = predict(model, g_attacked)

        clean_risks.append(clean)
        attacked_risks.append(attacked)
        deltas.append(attacked - clean)
        if (clean >= threshold) != (attacked >= threshold):
            flips += 1

    n = max(1, n_graphs)
    return EvaluationResult(
        attack_name=attack.name,
        budget=attack.config.budget,
        n_graphs=n_graphs,
        clean_mean=statistics.mean(clean_risks),
        clean_std=statistics.stdev(clean_risks) if n > 1 else 0.0,
        attacked_mean=statistics.mean(attacked_risks),
        attacked_std=statistics.stdev(attacked_risks) if n > 1 else 0.0,
        delta_mean=statistics.mean(deltas),
        delta_std=statistics.stdev(deltas) if n > 1 else 0.0,
        flip_rate=flips / n,
        threshold=threshold,
    )