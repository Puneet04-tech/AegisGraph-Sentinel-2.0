"""
CLI entry point for the adversarial robustness suite.

Run from the repo root:
    python -m src.adversarial
    python -m src.adversarial --attacks edge_addition feature_perturbation
    python -m src.adversarial --budgets 0.05 0.10 --n-graphs 100
    python -m src.adversarial --help
"""
from __future__ import annotations
import argparse
from pathlib import Path
import torch

from ..models.risk_model import FraudDetectionModel
from .base import AttackConfig
from .attacks import EdgeAddition, EdgeDeletion, NodeInjection, FeaturePerturbation, DecoyNodeInjection
from .evaluator import evaluate_attack
from .reporting import write_json_report, write_markdown_report, write_robustness_report


ATTACK_REGISTRY = {
    "edge_addition": EdgeAddition,
    "edge_deletion": EdgeDeletion,
    "node_injection": NodeInjection,
    "feature_perturbation": FeaturePerturbation,
    "decoy_node_injection": DecoyNodeInjection,
}


def load_model(checkpoint_path: Path) -> torch.nn.Module:
    """Load the HTGAT fraud detection model from a checkpoint.

    Architecture hyperparameters match example_training.py. If the maintainer
    changes those defaults, this loader needs to be updated to match.
    """
    model = FraudDetectionModel(
        node_feature_dim=32, hidden_dim=128, output_dim=64,
        num_node_types=5, num_edge_types=4,
        num_layers=2, heads=4, dropout=0.3,
    )
    ckpt = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
    model_state = ckpt.get("model_state_dict", ckpt)
    model.load_state_dict(model_state)
    return model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.adversarial",
        description="Evaluate adversarial robustness of the HTGAT fraud detection model.",
    )
    parser.add_argument(
        "--checkpoint", type=Path, default=Path("models/htgnn_final.pt"),
        help="Path to model checkpoint (default: models/htgnn_final.pt)",
    )
    parser.add_argument(
        "--attacks", nargs="+", choices=list(ATTACK_REGISTRY.keys()),
        default=list(ATTACK_REGISTRY.keys()),
        help="Which attacks to run (default: all)",
    )
    parser.add_argument(
        "--budgets", nargs="+", type=float,
        default=[0.01, 0.05, 0.10, 0.25, 0.50],
        help="Perturbation budgets to sweep (default: 0.01 0.05 0.10 0.25 0.50)",
    )
    parser.add_argument(
        "--n-graphs", type=int, default=50,
        help="Graphs to evaluate per (attack, budget) (default: 50)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("reports"),
        help="Directory for JSON and Markdown reports (default: reports/)",
    )
    parser.add_argument(
        "--threshold", type=float, default=0.5,
        help="Decision threshold for flip-rate metric (default: 0.5)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.checkpoint.exists():
        raise SystemExit(f"Checkpoint not found: {args.checkpoint}")

    model = load_model(args.checkpoint)
    print(f"Loaded checkpoint: {args.checkpoint}")
    print(f"Running {len(args.attacks)} attack(s) over {args.n_graphs} graphs at "
    f"{len(args.budgets)} budget(s) each.\n")

    all_results = []
    for attack_name in args.attacks:
        AttackCls = ATTACK_REGISTRY[attack_name]
        print(f"\n=== {AttackCls.name} ===")
        print(f"{'Budget':>8}  {'Clean':>10}  {'Attacked':>10}  {'Delta':>11}  {'Flips':>6}")
        print("-" * 52)
        for budget in args.budgets:
            attack = AttackCls(AttackConfig(budget=budget))
            r = evaluate_attack(
                model, attack,
                n_graphs=args.n_graphs,
                threshold=args.threshold,
            )
            all_results.append(r)
            print(f"{budget:>8.2%}  "
            f"{r.clean_mean:>10.4f}  "
            f"{r.attacked_mean:>10.4f}  "
            f"{r.delta_mean:>+11.4f}  "
            f"{r.flip_rate:>5.1%}")

    json_path = write_json_report(all_results, args.output_dir / "adversarial_results.json")
    md_path = write_markdown_report(all_results, args.output_dir / "adversarial_results.md")
    robustness_path = write_robustness_report(all_results, args.output_dir / "adversarial_robustness_report.md")
    print(f"\nJSON report:          {json_path}")
    print(f"Markdown report:      {md_path}")
    print(f"Robustness report:    {robustness_path}")


if __name__ == "__main__":
    main()