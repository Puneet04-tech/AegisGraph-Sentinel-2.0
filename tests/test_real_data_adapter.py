"""Tests for the real-data adapter (Elliptic Bitcoin -> HeteroData)."""

import csv
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("torch_geometric")

from src.data.real_data_adapter import build_graph  # noqa: E402

FEATURES = 165


def _row(tx_id: str, step: int, base: float) -> list:
    """One CSV row: txId, time step, then 165 numeric features."""
    return [tx_id, step] + [base * (index + 1) for index in range(FEATURES)]


def _write_raw(tmp_path: Path) -> Path:
    """Six transactions across time steps 1, 35 and 44 with a mix of labels."""
    rows = [
        _row("100", 1, 1.0),
        _row("101", 1, 3.0),
        _row("200", 35, 5.0),
        _row("201", 35, 7.0),
        _row("300", 44, 9.0),
        _row("301", 44, 11.0),
    ]
    with (tmp_path / "elliptic_txs_features.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerows(rows)

    classes = [("100", "1"), ("101", "2"), ("200", "1"), ("201", "2"), ("300", "unknown"), ("301", "2")]
    with (tmp_path / "elliptic_txs_classes.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["txId", "class"])
        writer.writerows(classes)

    edges = [("100", "101"), ("200", "101"), ("301", "300")]
    with (tmp_path / "elliptic_txs_edgelist.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["txId1", "txId2"])
        writer.writerows(edges)

    return tmp_path


def test_temporal_splits_follow_labeled_time_steps(tmp_path):
    data, report = build_graph(_write_raw(tmp_path))

    assert tuple(data["account"].x.shape) == (6, FEATURES)
    assert data["account"].time.tolist() == [1, 1, 35, 35, 44, 44]

    assert data["account"].train_mask.tolist() == [True, True, False, False, False, False]
    assert data["account"].val_mask.tolist() == [False, False, True, True, False, False]
    # Only labeled step-44 nodes are evaluated; the unknown one is excluded.
    assert data["account"].test_mask.tolist() == [False, False, False, False, False, True]

    assert report["splits"]["train"]["illicit"] == 1
    assert report["splits"]["test"]["nodes"] == 1
    assert report["splits"]["train"]["time_steps"] == [1, 1]


def test_labels_encode_illicit_as_one_and_keep_unknown_unsupervised(tmp_path):
    data, report = build_graph(_write_raw(tmp_path))

    assert data["account"].y.view(-1).tolist() == [1.0, 0.0, 1.0, 0.0, 0.0, 0.0]
    assert report["unknown_nodes"] == 1
    # txId 300 is unknown: present in the graph, never supervised.
    assert not bool(data["account"].test_mask[4])


def test_features_are_standardised_with_training_statistics_only(tmp_path):
    data, _ = build_graph(_write_raw(tmp_path))

    features = data["account"].x
    train_rows = features[data["account"].train_mask]
    assert torch.allclose(train_rows.mean(dim=0), torch.zeros(FEATURES), atol=1e-4)
    # Population std (ddof=0), matching the adapter's numpy normalisation.
    assert torch.allclose(train_rows.std(dim=0, unbiased=False), torch.ones(FEATURES), atol=1e-4)
    # Held-out rows keep their relative scale instead of being re-centred.
    assert not torch.allclose(features[2:].mean(dim=0), torch.zeros(FEATURES), atol=1e-3)


def test_edges_are_real_and_carry_no_edge_level_time(tmp_path):
    data, _ = build_graph(_write_raw(tmp_path))

    edge_type = ("account", "transacts", "account")
    assert data[edge_type].edge_index.tolist() == [[0, 2, 5], [1, 1, 4]]
    # Node-level time only: PyG's temporal sampler rejects time on both levels.
    assert "time" not in data[edge_type]
    assert "time" in data["account"]
    assert data.node_types == ["account"]


def test_rejects_files_with_the_wrong_column_count(tmp_path):
    raw = _write_raw(tmp_path)
    (raw / "elliptic_txs_features.csv").write_text("100,1,0.5\n", encoding="utf-8")

    with pytest.raises(ValueError, match="expected 167 columns"):
        build_graph(raw)
