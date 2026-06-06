"""
Report writers: turn a list of EvaluationResults into persisted JSON and
Markdown summaries.

JSON is the machine-readable form (full numerical precision, suitable for
downstream analysis or MLflow ingestion). Markdown is the human-readable
summary intended for PRs, READMEs, and issue comments.
"""
from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Union

from .evaluator import EvaluationResult


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json_report(results: Iterable[EvaluationResult], path: Union[Path, str]) -> Path:
    """Write all results to a JSON file. Returns the path written to."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "generated_at": _utc_now_iso(),
        "results": [asdict(r) for r in results],
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def write_markdown_report(results: Iterable[EvaluationResult], path: Union[Path, str]) -> Path:
    """Write a Markdown summary grouped by attack name. Returns the path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    results = list(results)

    by_attack: dict[str, List[EvaluationResult]] = {}
    for r in results:
        by_attack.setdefault(r.attack_name, []).append(r)

    lines: List[str] = []
    lines.append("# Adversarial Robustness Evaluation\n\n")
    lines.append(f"Generated: {_utc_now_iso()}\n\n")
    if results:
        lines.append(f"Graphs per (attack, budget): {results[0].n_graphs}\n")
        lines.append(f"Decision threshold: {results[0].threshold}\n")

    for attack_name, rs in by_attack.items():
        lines.append(f"\n## {attack_name}\n\n")
        lines.append("| Budget | Clean (mean ± std) | Attacked (mean ± std) | Delta (mean ± std) | Flip rate |\n")
        lines.append("|---|---|---|---|---|\n")
        for r in sorted(rs, key=lambda x: x.budget):
            lines.append(
                f"| {r.budget:.2%} | "
                f"{r.clean_mean:.4f} ± {r.clean_std:.4f} | "
                f"{r.attacked_mean:.4f} ± {r.attacked_std:.4f} | "
                f"{r.delta_mean:+.4f} ± {r.delta_std:.4f} | "
                f"{r.flip_rate:.1%} |\n"
            )

    with path.open("w", encoding="utf-8") as f:
        f.writelines(lines)
    return path


def write_robustness_report(results: Iterable[EvaluationResult], path: Union[Path, str]) -> Path:
    """Write GNN Adversarial Robustness and Decoy Node Injection report. Returns the path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    results = list(results)

    by_attack: dict[str, List[EvaluationResult]] = {}
    for r in results:
        by_attack.setdefault(r.attack_name, []).append(r)

    lines: List[str] = []
    lines.append("# GNN Adversarial Robustness & Decoy Node Injection Report\n\n")
    lines.append(f"**Generated:** {_utc_now_iso()}\n\n")
    
    if results:
        lines.append("## Executive Summary\n\n")
        lines.append(f"This report evaluates the resilience of the **HTGAT** GNN model under structural and feature attacks. ")
        lines.append(f"Evaluation was performed across **{results[0].n_graphs}** graph snapshots using a decision threshold of **{results[0].threshold}**.\n\n")
        lines.append("Specifically, we simulate a **Decoy Node Injection** attack where adversaries connect new dummy accounts ")
        lines.append("to high-centrality hubs to dilute their GNN risk signals. We measure the drop in standard classification metrics ")
        lines.append("(F1-Score, Precision, and Recall) to benchmark defensive robustness.\n\n")

    lines.append("## Adversarial Simulation Benchmarks\n")

    for attack_name, rs in by_attack.items():
        lines.append(f"\n### Attack Profile: `{attack_name}`\n\n")
        lines.append("| Budget | F1 (Clean → Attacked) | F1 Drop | Precision (Clean → Attacked) | Recall (Clean → Attacked) | Flip Rate |\n")
        lines.append("|---|---|---|---|---|---|\n")
        for r in sorted(rs, key=lambda x: x.budget):
            lines.append(
                f"| {r.budget:.2%} | "
                f"{r.clean_f1:.4f} → {r.attacked_f1:.4f} | "
                f"{r.f1_drop:+.4f} | "
                f"{r.clean_precision:.4f} → {r.attacked_precision:.4f} | "
                f"{r.clean_recall:.4f} → {r.attacked_recall:.4f} | "
                f"{r.flip_rate:.1%} |\n"
            )
        lines.append("\n")

    lines.append("## Evasion & Dilution Attack Summary\n\n")
    lines.append("1. **Decoy Node Injection Simulator**:\n")
    lines.append("   - Targets high-degree accounts (centrality hubs) and injects dummy nodes to simulate transaction masking.\n")
    lines.append("   - A high degradation in F1-score indicates the model is highly sensitive to topological changes that mask existing hubs.\n")
    lines.append("2. **Structural Perturbations**:\n")
    lines.append("   - Random edge addition or deletion alters the attention coefficients computed by the multi-head HTGAT layers, leading to flipped classification thresholds.\n\n")

    lines.append("## Defensive Recommendations\n\n")
    lines.append("- **Adversarial Training**: Augment the training loader with structural perturbations during batch preparation.\n")
    lines.append("- **Centrality Hardening**: Incorporate topological invariant heuristics that are resilient to simple star-graph decoy attachments (e.g. core-decomposition prune-steps).\n")
    lines.append("- **Feature-Structure Alignment**: Train the risk prediction head using a contrastive loss aligning raw transaction features with local subgraph topology to prevent topological evasion.\n")

    with path.open("w", encoding="utf-8") as f:
        f.writelines(lines)
    return path