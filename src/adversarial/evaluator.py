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
    clean_f1: float
    clean_precision: float
    clean_recall: float
    attacked_f1: float
    attacked_precision: float
    attacked_recall: float
    f1_drop: float
    precision_drop: float
    recall_drop: float


def build_synthetic_graph(num_nodes=30, num_edges=60, feature_dim=32, seed=0) -> Graph:
    """One synthetic graph matching example_training.py's format."""
    gen = torch.Generator().manual_seed(seed)
    y = 1.0 if seed % 10 >= 7 else 0.0
    return {
        "x": torch.randn(num_nodes, feature_dim, generator=gen),
        "edge_index": torch.randint(0, num_nodes, (2, num_edges), generator=gen),
        "node_type": torch.randint(0, 5, (num_nodes,), generator=gen),
        "edge_type": torch.randint(0, 4, (num_edges,), generator=gen),
        "edge_timestamp": torch.rand(num_edges, generator=gen) * 86400,
        "y": torch.tensor(y, dtype=torch.float),
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


def _calculate_metrics(y_true: List[float], y_pred_prob: List[float], threshold: float) -> tuple[float, float, float]:
    tp = fp = fn = tn = 0
    for true, prob in zip(y_true, y_pred_prob):
        pred = 1.0 if prob >= threshold else 0.0
        if true == 1.0:
            if pred == 1.0:
                tp += 1
            else:
                fn += 1
        else:
            if pred == 1.0:
                fp += 1
            else:
                tn += 1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return float(f1), float(precision), float(recall)


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
    y_true: List[float] = []
    flips = 0

    model.eval()

    for i in range(n_graphs):
        g = graph_builder(seed=i)
        attack.config.seed = i + seed_offset
        g_attacked = attack.perturb(g)

        clean = predict(model, g)
        attacked = predict(model, g_attacked)

        y_val = float(g.get("y", torch.tensor(1.0 if i % 10 >= 7 else 0.0)).item())
        y_true.append(y_val)

        clean_risks.append(clean)
        attacked_risks.append(attacked)
        deltas.append(attacked - clean)
        if (clean >= threshold) != (attacked >= threshold):
            flips += 1

    n = max(1, n_graphs)
    
    clean_f1, clean_prec, clean_rec = _calculate_metrics(y_true, clean_risks, threshold)
    att_f1, att_prec, att_rec = _calculate_metrics(y_true, attacked_risks, threshold)
    
    f1_drop = clean_f1 - att_f1
    prec_drop = clean_prec - att_prec
    rec_drop = clean_rec - att_rec

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
        clean_f1=clean_f1,
        clean_precision=clean_prec,
        clean_recall=clean_rec,
        attacked_f1=att_f1,
        attacked_precision=att_prec,
        attacked_recall=att_rec,
        f1_drop=f1_drop,
        precision_drop=prec_drop,
        recall_drop=rec_drop,
    )