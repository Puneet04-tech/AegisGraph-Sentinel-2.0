"""Build a training graph from a real, publicly available fraud dataset.

The synthetic generator fabricates a heterogeneous ``account``/``device``
graph. Real data rarely arrives in that shape, so this adapter converts the
Elliptic Bitcoin dataset (Weber et al., 2019) into the same artifact contract:

    data['account'].x            float [N, 165]   real transaction features
    data['account'].y            float [N, 1]     illicit=1, licit=0
    data['account'].time         long  [N]        real time step (1..49)
    data['account'].train_mask   bool  [N]        labeled & step <= 34
    data['account'].val_mask     bool  [N]        labeled & 35 <= step <= 41
    data['account'].test_mask    bool  [N]        labeled & step >= 42
    data['account'].tx_id        list  [N]        original transaction ids (serving lookup)
    data['account', 'transacts', 'account'].edge_index   real payment edges

There is no device entity in this dataset, so the ``device`` node type and the
``('device', 'logs_into', 'account')`` relation are deliberately absent rather
than invented; the loader and model both accept a device-free graph.

Provenance: raw CSVs are the unmodified Elliptic files (txId, time step,
f1..f165; classes 1=illicit, 2=licit, unknown; directed payment edges).
Feature standardisation uses statistics from the training split only, so no
validation or test information leaks into preprocessing.

Usage:
    python -m src.data.real_data_adapter --raw-dir data/real/raw \
        --out data/real/elliptic_aegis.pt
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Dict, Tuple

import numpy as np
import torch
from torch_geometric.data import HeteroData

FEATURE_COLUMNS = 167  # txId + time step + 165 features (the file has no header)
TRAIN_LAST_STEP = 34
VALID_LAST_STEP = 41


def _read_features(path: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (tx_ids, time_steps, features) from the raw feature CSV."""
    try:
        import pandas as pd
    except ImportError:  # pragma: no cover - pandas is an optional dependency
        pd = None

    if pd is not None:
        frame = pd.read_csv(path, header=None)
        if frame.shape[1] != FEATURE_COLUMNS:
            raise ValueError(
                f"expected {FEATURE_COLUMNS} columns in {path}, got {frame.shape[1]}"
            )
        tx_ids = frame.iloc[:, 0].astype(str).to_numpy()
        steps = frame.iloc[:, 1].astype(np.int64).to_numpy()
        features = frame.iloc[:, 2:].to_numpy(dtype=np.float32)
        return tx_ids, steps, features

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        ids: list[str] = []
        step_list: list[int] = []
        rows: list[list[float]] = []
        for row in reader:
            if len(row) != FEATURE_COLUMNS:
                raise ValueError(
                    f"expected {FEATURE_COLUMNS} columns in {path}, got {len(row)}"
                )
            ids.append(row[0])
            step_list.append(int(float(row[1])))
            rows.append([float(value) for value in row[2:]])
    return (
        np.asarray(ids),
        np.asarray(step_list, dtype=np.int64),
        np.asarray(rows, dtype=np.float32),
    )


def _read_classes(path: Path) -> Dict[str, int]:
    """Map txId to 1 (illicit), 0 (licit) or -1 (unknown)."""
    labels: Dict[str, int] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            raw = str(row["class"]).strip()
            if raw == "1":
                labels[row["txId"].strip()] = 1
            elif raw == "2":
                labels[row["txId"].strip()] = 0
            else:
                labels[row["txId"].strip()] = -1
    return labels


def _read_edges(path: Path) -> list[Tuple[str, str]]:
    edges: list[Tuple[str, str]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            edges.append((row["txId1"].strip(), row["txId2"].strip()))
    return edges


def build_graph(raw_dir: Path) -> Tuple[HeteroData, dict]:
    """Convert the raw Elliptic CSVs into a HeteroData training artifact."""
    tx_ids, steps, features = _read_features(raw_dir / "elliptic_txs_features.csv")
    labels = _read_classes(raw_dir / "elliptic_txs_classes.csv")
    raw_edges = _read_edges(raw_dir / "elliptic_txs_edgelist.csv")

    index_of = {tx_id: idx for idx, tx_id in enumerate(tx_ids)}
    num_nodes = len(tx_ids)

    y = np.full(num_nodes, -1, dtype=np.int64)
    for tx_id, label in labels.items():
        idx = index_of.get(tx_id)
        if idx is not None:
            y[idx] = label
    labeled = y >= 0

    # Temporal splits on labeled nodes only: later time steps are never seen
    # during training, so the evaluation measures forward-looking detection.
    train_mask = labeled & (steps <= TRAIN_LAST_STEP)
    val_mask = labeled & (steps > TRAIN_LAST_STEP) & (steps <= VALID_LAST_STEP)
    test_mask = labeled & (steps > VALID_LAST_STEP)

    # Standardisation statistics come from the training split only.
    train_rows = features[train_mask]
    mean = train_rows.mean(axis=0)
    std = train_rows.std(axis=0)
    std[std < 1e-6] = 1.0
    normalised = (features - mean) / std

    src: list[int] = []
    dst: list[int] = []
    for left, right in raw_edges:
        i, j = index_of.get(left), index_of.get(right)
        if i is None or j is None:
            continue
        src.append(i)
        dst.append(j)
    edge_index = torch.tensor([src, dst], dtype=torch.long)

    data = HeteroData()
    data["account"].x = torch.from_numpy(normalised.astype(np.float32))
    # Unknown nodes carry no supervision; their label is ignored by the masks.
    data["account"].y = torch.from_numpy((y == 1).astype(np.float32)).view(-1, 1)
    data["account"].time = torch.from_numpy(steps.astype(np.int64))
    data["account"].train_mask = torch.from_numpy(train_mask)
    data["account"].val_mask = torch.from_numpy(val_mask)
    data["account"].test_mask = torch.from_numpy(test_mask)
    # Keep the original transaction ids so serving can resolve an account back
    # to its row (and therefore to its neighbourhood) without re-reading the
    # raw CSVs. Row order is the file's order, so this stays aligned with any
    # checkpoint trained on this artifact.
    data["account"].tx_id = [str(tx_id) for tx_id in tx_ids]
    data["account", "transacts", "account"].edge_index = edge_index
    # No edge-level ``time`` on purpose: Elliptic edges carry no timestamp of
    # their own, and PyG's temporal sampler only accepts time on one level. The
    # node-level time step above already bounds when an edge is observable.

    report = {
        "source": "Elliptic Bitcoin Dataset (Weber et al., 2019)",
        "raw_dir": str(raw_dir),
        "nodes": int(num_nodes),
        "edges": int(edge_index.size(1)),
        "features": int(features.shape[1]),
        "time_steps": int(steps.max()),
        "labeled_nodes": int(labeled.sum()),
        "illicit_nodes": int((y == 1).sum()),
        "licit_nodes": int((y == 0).sum()),
        "unknown_nodes": int((y == -1).sum()),
        "splits": {
            "train": {
                "nodes": int(train_mask.sum()),
                "illicit": int((y[train_mask] == 1).sum()),
                "time_steps": [int(steps[train_mask].min()), int(steps[train_mask].max())],
            },
            "val": {
                "nodes": int(val_mask.sum()),
                "illicit": int((y[val_mask] == 1).sum()),
                "time_steps": [int(steps[val_mask].min()), int(steps[val_mask].max())],
            },
            "test": {
                "nodes": int(test_mask.sum()),
                "illicit": int((y[test_mask] == 1).sum()),
                "time_steps": [int(steps[test_mask].min()), int(steps[test_mask].max())],
            },
        },
        "has_tx_ids": True,
        "node_types": list(data.node_types),
        "edge_types": [[str(part) for part in key] for key in data.edge_types],
    }
    return data, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", default="data/real/raw")
    parser.add_argument("--out", default="data/real/elliptic_aegis.pt")
    args = parser.parse_args()

    raw_dir = Path(args.raw_dir)
    data, report = build_graph(raw_dir)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(data, out_path)

    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()
    report["artifact"] = str(out_path)
    report["sha256"] = digest
    report_path = out_path.with_suffix(".report.json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    print(
        "\nUse it with:\n"
        f"  AEGIS_GRAPH_PATH={out_path}\n"
        f"  AEGIS_GRAPH_SHA256={digest}"
    )


if __name__ == "__main__":
    main()
