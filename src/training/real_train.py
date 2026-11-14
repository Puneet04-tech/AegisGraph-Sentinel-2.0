"""Train the HTGNN on a real fraud graph with a strict temporal protocol.

``src/training/train.py`` trains on the synthetic graph through a
``NeighborLoader``. Real payment graphs need two extra guarantees that the
sampler would otherwise provide, and that ``pyg-lib``/``torch-sparse`` (not
installable on every platform) normally implement:

1. **No future information.** For every time step ``t`` the model only ever
   sees the subgraph induced by nodes with ``time <= t``, then scores the
   labeled transactions that happened exactly at ``t``. A node can therefore
   never aggregate over a transaction that had not happened yet.
2. **No label noise.** The loss is computed only on labeled root nodes inside
   the split masks; unknown transactions (the majority of the Elliptic graph)
   contribute no supervision instead of being silently treated as licit.

Usage (Elliptic Bitcoin, built by ``src.data.real_data_adapter``):
    python -m src.training.real_train --graph data/real/elliptic_aegis.pt \
        --epochs 6 --out models/htgnn_elliptic_v1.pt
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score
from torch.optim import AdamW

from ..models.htgnn import AegisHTGNN
from ..utils.encryption import get_encryption_handler
from .data_loader import _allow_pyg_safe_globals

logger = logging.getLogger(__name__)


def load_graph(path: Path) -> "torch_geometric.data.HeteroData":
    """Load a verified graph artifact produced by the real-data adapter."""
    _allow_pyg_safe_globals()
    data = torch.load(path, weights_only=True)
    for required in ("x", "y", "time", "train_mask", "val_mask", "test_mask"):
        if required not in data["account"]:
            raise ValueError(f"graph artifact {path} is missing account.{required}")
    if ("account", "transacts", "account") not in data.edge_types:
        raise ValueError(f"graph artifact {path} has no account->account transactions")
    return data


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class TemporalSnapshots:
    """Builds time-respecting subgraphs lazily, one per time step.

    ``window`` bounds how far back a snapshot looks (``t - window <= time <= t``).
    It plays the role of a neighbour sampler's hop budget: recent transactions
    carry the mule signal, and skipping year-old history keeps each forward
    pass small enough to train on a CPU.
    """

    def __init__(self, data, window: int = 8) -> None:
        self.x = data["account"].x.float()
        self.y = data["account"].y.float().view(-1)
        self.time = data["account"].time.long()
        self.edge_index = data[("account", "transacts", "account")].edge_index.long()
        self.train_mask = data["account"].train_mask.bool()
        self.val_mask = data["account"].val_mask.bool()
        self.test_mask = data["account"].test_mask.bool()
        self.steps: List[int] = sorted(int(t) for t in self.time.unique())
        self.window = max(int(window), 0)

    def subgraph(self, step: int) -> Tuple[torch.Tensor, Dict, torch.Tensor]:
        """Return (features, edge_index_dict, local ids) for the visible window."""
        keep = (self.time <= step) & (self.time >= step - self.window)
        local = torch.nonzero(keep, as_tuple=False).view(-1)
        remap = torch.full((self.time.numel(),), -1, dtype=torch.long)
        remap[local] = torch.arange(local.numel())

        src, dst = self.edge_index
        edge_keep = keep[src] & keep[dst]
        edges = remap[self.edge_index[:, edge_keep]]
        return (
            self.x[local],
            {("account", "transacts", "account"): edges},
            local,
        )


def evaluate(model, snapshots: TemporalSnapshots, mask: torch.Tensor) -> Dict[str, float]:
    """Score every labeled node in ``mask`` at its own time step, without leakage."""
    model.eval()
    probs: List[np.ndarray] = []
    labels: List[np.ndarray] = []
    steps = sorted(int(t) for t in snapshots.time[mask].unique())
    with torch.no_grad():
        for step in steps:
            x, edge_index_dict, local = snapshots.subgraph(step)
            logits = model({"account": x}, edge_index_dict).view(-1)
            roots_global = torch.nonzero(mask & (snapshots.time == step), as_tuple=False).view(-1)
            roots_local = torch.searchsorted(local, roots_global)
            probs.append(torch.sigmoid(logits[roots_local]).cpu().numpy())
            labels.append(snapshots.y[roots_global].cpu().numpy())

    y_true = np.concatenate(labels)
    y_prob = np.concatenate(probs)
    if y_true.min() == y_true.max():  # a split with one class has no ranking metric
        return {"auc": float("nan"), "ap": float("nan"), "f1": float("nan"), "n": int(y_true.size)}
    return {
        "auc": float(roc_auc_score(y_true, y_prob)),
        "ap": float(average_precision_score(y_true, y_prob)),
        "f1": float(f1_score(y_true, (y_prob >= 0.5).astype(int))),
        "n": int(y_true.size),
        "illicit": int(y_true.sum()),
        "_prob": y_prob,
        "_true": y_true,
    }


def _best_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> Tuple[float, float]:
    """Pick the F1-maximising threshold on the validation split only."""
    best_threshold, best_f1 = 0.5, 0.0
    for threshold in np.linspace(0.05, 0.95, 19):
        score = f1_score(y_true, (y_prob >= threshold).astype(int))
        if score > best_f1:
            best_threshold, best_f1 = float(threshold), float(score)
    return best_threshold, best_f1


def train(
    data,
    *,
    epochs: int = 6,
    hidden_channels: int = 32,
    heads: int = 4,
    num_layers: int = 2,
    dropout: float = 0.3,
    lr: float = 1e-3,
    weight_decay: float = 1e-4,
    window: int = 8,
    seed: int = 42,
) -> Tuple[AegisHTGNN, Dict]:
    torch.manual_seed(seed)
    np.random.seed(seed)

    snapshots = TemporalSnapshots(data, window=window)
    features = int(data["account"].x.size(1))
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model = AegisHTGNN(
        hidden_channels=hidden_channels,
        out_channels=1,
        num_layers=num_layers,
        heads=heads,
        dropout=dropout,
        node_channels={"account": features},
        edge_types=[("account", "transacts", "account")],
    ).to(device)

    # Illicit transactions are ~1 in 7 labeled nodes; weight the positive class
    # so a model that predicts "licit" everywhere cannot minimise the loss.
    train_labels = snapshots.y[snapshots.train_mask]
    positives = float(train_labels.sum())
    negatives = float(train_labels.numel() - positives)
    pos_weight = torch.tensor([negatives / max(positives, 1.0)], device=device)

    optimizer = AdamW(model.parameters(), lr=lr, weight_decay=weight_decay, eps=1e-8)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=max(epochs, 1), eta_min=1e-6)

    train_steps = [s for s in snapshots.steps if bool(snapshots.train_mask[snapshots.time == s].any())]
    history: List[Dict] = []
    started = time.time()

    # Keep the weights from the epoch with the best validation AUC. Validation
    # AUC peaks early on this dataset and then decays as the model overfits the
    # training time steps; persisting the final epoch would ship the worse
    # model. Selection uses the validation split only, never the test split.
    best_state = {key: value.detach().clone() for key, value in model.state_dict().items()}
    best_auc, best_epoch = float("-inf"), 0

    for epoch in range(1, epochs + 1):
        model.train()
        epoch_loss, epoch_nodes = 0.0, 0
        for index, step in enumerate(train_steps, start=1):
            if index % 10 == 0:
                logger.info("  epoch %d: snapshot %d/%d (time step %d)", epoch, index, len(train_steps), step)
            x, edge_index_dict, local = snapshots.subgraph(step)
            roots_global = torch.nonzero(
                snapshots.train_mask & (snapshots.time == step), as_tuple=False
            ).view(-1)
            roots_local = torch.searchsorted(local, roots_global)

            optimizer.zero_grad()
            logits = model({"account": x.to(device)}, edge_index_dict).view(-1)
            loss = F.binary_cross_entropy_with_logits(
                logits[roots_local.to(device)],
                snapshots.y[roots_global].to(device),
                pos_weight=pos_weight,
            )
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            epoch_loss += float(loss.detach()) * roots_global.numel()
            epoch_nodes += roots_global.numel()

        scheduler.step()
        validation = evaluate(model, snapshots, snapshots.val_mask)
        record = {
            "epoch": epoch,
            "train_loss": epoch_loss / max(epoch_nodes, 1),
            "lr": optimizer.param_groups[0]["lr"],
            "val_auc": validation["auc"],
            "val_ap": validation["ap"],
            "val_f1": validation["f1"],
        }
        history.append(record)
        if validation["auc"] == validation["auc"] and validation["auc"] > best_auc:
            best_auc, best_epoch = validation["auc"], epoch
            best_state = {
                key: value.detach().clone() for key, value in model.state_dict().items()
            }
        logger.info(
            "epoch %d | loss %.4f | val AUC %.4f | val AP %.4f | val F1 %.4f",
            epoch,
            record["train_loss"],
            record["val_auc"],
            record["val_ap"],
            record["val_f1"],
        )

    if best_epoch:
        model.load_state_dict(best_state)
        logger.info("restored weights from epoch %d (val AUC %.4f)", best_epoch, best_auc)

    validation = evaluate(model, snapshots, snapshots.val_mask)
    threshold, val_best_f1 = _best_threshold(validation["_true"], validation["_prob"])
    test = evaluate(model, snapshots, snapshots.test_mask)
    test_f1_at_val_threshold = float(
        f1_score(test["_true"], (test["_prob"] >= threshold).astype(int))
    )

    report = {
        "epochs": epochs,
        "features": features,
        "hidden_channels": hidden_channels,
        "pos_weight": float(pos_weight),
        "train_steps": [train_steps[0], train_steps[-1]],
        "seconds": round(time.time() - started, 1),
        "history": history,
        "best_epoch": best_epoch,
        "best_val_auc": best_auc,
        "validation": {k: v for k, v in validation.items() if not k.startswith("_")},
        "test": {k: v for k, v in test.items() if not k.startswith("_")},
        "chosen_threshold": threshold,
        "validation_f1_at_threshold": val_best_f1,
        "test_f1_at_threshold": test_f1_at_val_threshold,
    }
    return model, report


def main() -> None:
    parser = argparse.ArgumentParser(description="Train HTGNN on real graph data")
    parser.add_argument("--graph", default="data/real/elliptic_aegis.pt")
    parser.add_argument("--sha256", default=None, help="expected artifact digest")
    parser.add_argument("--epochs", type=int, default=6)
    parser.add_argument("--hidden", type=int, default=32)
    parser.add_argument("--heads", type=int, default=4)
    parser.add_argument("--layers", type=int, default=2)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument(
        "--window",
        type=int,
        default=8,
        help="time steps of history visible to each snapshot",
    )
    parser.add_argument("--out", default="models/htgnn_elliptic_v1.pt")
    parser.add_argument("--report", default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Saving a checkpoint needs MODEL_ENCRYPTION_KEY, which lives in the
    # project's .env for local runs; the encryption helper reads os.environ
    # directly, so load the file before it is constructed.
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:  # pragma: no cover - python-dotenv is a project dependency
        pass

    graph_path = Path(args.graph)
    digest = _sha256(graph_path)
    if args.sha256 and digest != args.sha256:
        raise SystemExit(f"artifact digest mismatch: {digest} != {args.sha256}")

    data = load_graph(graph_path)
    logger.info(
        "graph: %s accounts, %s edges (sha256 %s)",
        int(data["account"].num_nodes),
        int(data[("account", "transacts", "account")].num_edges),
        digest[:16],
    )

    model, report = train(
        data,
        epochs=args.epochs,
        hidden_channels=args.hidden,
        heads=args.heads,
        num_layers=args.layers,
        lr=args.lr,
        window=args.window,
    )
    report["graph"] = str(graph_path)
    report["graph_sha256"] = digest

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "node_channels": model.node_channels,
        "edge_types": [list(key) for key in model.edge_types],
        "hidden_channels": model.hidden_channels,
        "report": report,
    }
    out_path.write_bytes(get_encryption_handler().encrypt_checkpoint(checkpoint))
    report["artifact"] = str(out_path)

    report_path = Path(args.report) if args.report else out_path.with_suffix(".report.json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(
        json.dumps(
            {
                "validation": report["validation"],
                "test": report["test"],
                "chosen_threshold": report["chosen_threshold"],
                "test_f1_at_threshold": report["test_f1_at_threshold"],
                "seconds": report["seconds"],
                "artifact": report["artifact"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
