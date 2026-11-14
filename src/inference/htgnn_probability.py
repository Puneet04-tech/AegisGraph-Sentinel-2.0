"""Serve the trained HTGNN checkpoint to the risk scorer.

The training pipeline writes an AES-encrypted checkpoint
(``models/htgnn_elliptic_v1.pt``) together with the architecture metadata the
model needs to be rebuilt: ``node_channels``, ``edge_types`` and
``hidden_channels``. Head count and depth are recovered from the weight shapes,
so a checkpoint stays loadable without retraining if the metadata is partial.

Scoring a single transaction needs no neighbourhood: ``AegisHTGNN`` keeps a skip
connection from the encoded node features into the classifier, so a node with no
edges is still scored from its own features rather than from a bias term.

Everything here is best-effort by design. A missing checkpoint, an unreadable
key, a dimension mismatch or an inference error must degrade to the rule-based
scorer with a reason, never turn a fraud check into a 500.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

from ..observability import get_logger

logger = get_logger("inference.htgnn_probability")

DEFAULT_CHECKPOINT = "models/htgnn_elliptic_v1.pt"
CHECKPOINT_ENV_VAR = "AEGIS_MODEL_CHECKPOINT"
GRAPH_ENV_VAR = "AEGIS_MODEL_GRAPH"
DEFAULT_GRAPH = "data/real/elliptic_aegis.pt"
WINDOW_ENV_VAR = "AEGIS_MODEL_WINDOW"
DEFAULT_WINDOW = 10
# Flat probabilities are cheap to keep, so cache plenty of recently scored
# transactions; a lookup is then a dict hit for repeat ids.
LOOKUP_CACHE_SIZE = 4096

_MODEL_CACHE: Dict[str, "HTGNNProbabilityModel"] = {}
_CACHE_LOCK = threading.Lock()


def _derive_architecture(state: Dict[str, Any], hidden_channels: int) -> Dict[str, int]:
    """Recover head count and layer count from the saved weight shapes."""
    heads = 1
    encoder = state.get("hgt.convs.0.k_linears.0.weight")
    if encoder is not None and hidden_channels > 0:
        heads = max(1, int(encoder.shape[0]) // int(hidden_channels))

    layers = 0
    while f"hgt.convs.{layers}.q_linears.0.weight" in state:
        layers += 1
    return {"heads": heads, "num_layers": max(layers, 1)}


class GraphContextIndex:
    """Scores a transaction together with the neighbours visible at its time.

    This reproduces the training-time protocol exactly: for a transaction at
    step ``t`` the model sees the subgraph with ``t - window <= time <= t`` and
    its logit is read out of that pass. Loading the artifact is done on a
    background thread so no fraud check ever waits for it; until it is ready the
    caller falls back to the rule path.
    """

    def __init__(self, path: Path, model: "HTGNNProbabilityModel", window: int) -> None:
        self.path = Path(path)
        self.model = model
        self.window = max(int(window), 0)
        self.state = "loading"
        self.error: Optional[str] = None
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._cache: "OrderedDict[int, float]" = OrderedDict()
        self.layers = max(int(getattr(model, "num_layers", 2) or 2), 1)

    # -- loading ---------------------------------------------------------
    def start_loading(self) -> None:
        thread = threading.Thread(
            target=self.load, name="htgnn-graph-context", daemon=True
        )
        thread.start()

    def load(self) -> bool:
        if self._ready.is_set():
            return self.state == "ready"
        try:
            import torch

            from ..training.data_loader import _allow_pyg_safe_globals

            _allow_pyg_safe_globals()
            data = torch.load(self.path, weights_only=True)
            store = data["account"]
            tx_ids = getattr(store, "tx_id", None)
            if not tx_ids:
                raise ValueError("graph artifact has no account.tx_id values")

            self._x = store.x.float()
            self._time = store.time.long()
            self._edges = data[("account", "transacts", "account")].edge_index.long()
            self._tx_ids = [str(value) for value in tx_ids]
            self._row_of = {tx_id: row for row, tx_id in enumerate(self._tx_ids)}
            self._num_nodes = self._x.size(0)
            if self._time.numel() != self._num_nodes:
                raise ValueError("graph artifact time steps do not match node count")

            self.state = "ready"
            logger.info(
                f"Loaded graph context from {self.path} ({self._num_nodes} nodes)",
                event_type="model_graph_context_loaded",
                metadata={"nodes": int(self._num_nodes), "window": self.window},
            )
        except Exception as exc:
            self.state = "unavailable"
            self.error = str(exc)
            logger.warning(
                f"Graph context unavailable ({self.path}); rule scoring stays active",
                event_type="model_graph_context_failed",
                metadata={"error": str(exc)},
            )
        finally:
            self._ready.set()
        return self.state == "ready"

    def wait(self, timeout: Optional[float] = None) -> bool:
        self._ready.wait(timeout)
        return self.state == "ready"

    # -- lookup ----------------------------------------------------------
    def probabilities_for(self, accounts: Sequence[str]) -> Dict[str, float]:
        """Map known transaction ids to their fraud probability."""
        if self.state != "ready" or not accounts:
            return {}

        resolved: Dict[str, float] = {}
        with self._lock:
            for account in accounts:
                tx_id = str(account)
                row = self._row_of.get(tx_id)
                if row is None:
                    continue
                probability = self._cache.get(row)
                if probability is None:
                    probability = self._score_row(row)
                    self._cache[row] = probability
                    while len(self._cache) > LOOKUP_CACHE_SIZE:
                        self._cache.popitem(last=False)
                resolved[tx_id] = probability
        return resolved

    def _upstream_closure(self, row: int):
        """Rows the model can actually see when scoring ``row``.

        The network has no normalisation layers, so a transaction's logit is a
        function of its own features and of the ``layers`` hops of incoming
        messages reachable inside the time window. Nothing else can reach it,
        which is why this closure reproduces a full-window pass exactly while
        scoring a few hundred nodes instead of tens of thousands.
        """
        import torch

        step = int(self._time[row])
        in_window = (self._time <= step) & (self._time >= step - self.window)
        src, dst = self._edges

        visited = torch.tensor([row], dtype=torch.long)
        frontier = visited
        for _ in range(self.layers):
            if frontier.numel() == 0:
                break
            predecessors = src[torch.isin(dst, frontier)]
            predecessors = predecessors[in_window[predecessors]]
            new = predecessors[~torch.isin(predecessors, visited)]
            if new.numel() == 0:
                break
            visited = torch.unique(torch.cat([visited, new]))
            frontier = torch.unique(new)
        return visited, in_window

    def _score_row(self, row: int) -> float:
        import torch

        local, in_window = self._upstream_closure(row)
        remap = torch.full((self._num_nodes,), -1, dtype=torch.long)
        remap[local] = torch.arange(local.numel())

        src, dst = self._edges
        edge_keep = in_window[src] & in_window[dst]
        edge_keep &= remap[src] >= 0
        edge_keep &= remap[dst] >= 0
        sub_edges = remap[self._edges[:, edge_keep]]

        scores = np.asarray(
            self.model.predict_proba(self._x[local].numpy(), sub_edges.numpy()),
            dtype=np.float64,
        )
        if scores.shape[0] != local.numel():
            raise RuntimeError("graph context scoring returned a mismatched row count")

        position = int((local == row).nonzero(as_tuple=False).view(-1)[0])
        return float(scores[position])


class HTGNNProbabilityModel:
    """Thin, thread-safe wrapper that turns features into a fraud probability."""

    def __init__(
        self,
        checkpoint_path: str | os.PathLike,
        device: Optional[str] = None,
        graph_path: Optional[str | os.PathLike] = None,
        window: Optional[int] = None,
    ) -> None:
        self.checkpoint_path = Path(checkpoint_path)
        self._device_name = device
        self._model = None
        self._torch = None
        self._input_dim: Optional[int] = None
        self._lock = threading.Lock()
        self.load_error: Optional[str] = None
        self._graph_path = Path(
            graph_path or os.environ.get(GRAPH_ENV_VAR) or DEFAULT_GRAPH
        )
        self._window = int(
            window if window is not None else os.environ.get(WINDOW_ENV_VAR) or DEFAULT_WINDOW
        )
        self._graph: Optional[GraphContextIndex] = None

    # -- loading ---------------------------------------------------------
    def _load(self):
        if self._model is not None:
            return self._model
        with self._lock:
            if self._model is not None:
                return self._model

            import torch

            from ..models.htgnn import AegisHTGNN
            from ..utils.encryption import get_encryption_handler

            payload = self.checkpoint_path.read_bytes()
            checkpoint = get_encryption_handler().decrypt_checkpoint(payload)
            state = checkpoint.get("model_state_dict") or checkpoint
            node_channels = checkpoint.get("node_channels") or {}
            edge_types = checkpoint.get("edge_types") or []

            if not node_channels or "account" not in node_channels:
                raise ValueError("checkpoint does not describe its node features")
            if not edge_types:
                raise ValueError("checkpoint does not describe its edge types")

            hidden = int(checkpoint.get("hidden_channels") or 0)
            if hidden <= 0:
                raise ValueError("checkpoint is missing hidden_channels")
            architecture = _derive_architecture(state, hidden)

            model = AegisHTGNN(
                hidden_channels=hidden,
                out_channels=1,
                num_layers=architecture["num_layers"],
                heads=architecture["heads"],
                node_channels=node_channels,
                edge_types=[tuple(key) for key in edge_types],
            )
            model.load_state_dict(state, strict=True)

            device = self._device_name or ("cuda" if torch.cuda.is_available() else "cpu")
            self._model = model.to(device).eval()
            self._torch = torch
            self._input_dim = int(node_channels["account"])
            self._num_layers = int(architecture["num_layers"])
            self._edge_types = [tuple(key) for key in edge_types]
            self.load_error = None
            logger.info(
                f"Loaded HTGNN checkpoint {self.checkpoint_path}",
                event_type="model_checkpoint_loaded",
                metadata={
                    "hidden_channels": hidden,
                    "heads": architecture["heads"],
                    "layers": architecture["num_layers"],
                    "features": self._input_dim,
                },
            )
        return self._model

    @property
    def feature_dim(self) -> Optional[int]:
        """Input feature width expected by the checkpoint, or None if unloaded."""
        try:
            self._load()
        except Exception as exc:  # pragma: no cover - exercised via availability
            self.load_error = str(exc)
            return None
        return self._input_dim

    def is_available(self) -> bool:
        return self.feature_dim is not None

    @property
    def num_layers(self) -> Optional[int]:
        """Message-passing hops the checkpoint applies (its receptive field)."""
        return self._num_layers if self._model is not None else None

    # -- inference -------------------------------------------------------
    def predict_proba(
        self,
        features: Sequence[Sequence[float]] | np.ndarray,
        edge_index: Optional[np.ndarray] = None,
    ) -> List[float]:
        """Return one fraud probability per feature row.

        ``edge_index`` is optional; without it every row is scored from its own
        features through the model's skip connection.
        """
        model = self._load()
        torch = self._torch

        array = np.asarray(features, dtype=np.float32)
        if array.ndim == 1:
            array = array.reshape(1, -1)
        if array.ndim != 2:
            raise ValueError("features must be a 1-D or 2-D array")
        if array.shape[1] != self._input_dim:
            raise ValueError(
                f"expected {self._input_dim} features per transaction, got {array.shape[1]}"
            )
        if not np.isfinite(array).all():
            raise ValueError("features contain NaN or infinite values")

        device = next(model.parameters()).device
        edge_type = self._edge_types[0]
        if edge_index is None:
            edges = torch.zeros((2, 0), dtype=torch.long)
        else:
            edges = torch.as_tensor(np.asarray(edge_index, dtype=np.int64), dtype=torch.long)
            if edges.dim() != 2 or edges.size(0) != 2:
                raise ValueError("edge_index must have shape [2, num_edges]")

        with torch.no_grad():
            logits = model(
                {"account": torch.as_tensor(array, dtype=torch.float32, device=device)},
                {edge_type: edges.to(device)},
            )
        return torch.sigmoid(logits).view(-1).cpu().tolist()

    # -- graph context ---------------------------------------------------
    def ensure_graph_context(self) -> None:
        """Start building the transaction -> neighbourhood index once."""
        if self._graph is not None or not self._graph_path.is_file():
            return
        index = None
        with self._lock:
            if self._graph is None and self._graph_path.is_file():
                self._graph = index = GraphContextIndex(
                    self._graph_path, self, self._window
                )
        if index is not None:
            index.start_loading()

    @property
    def graph_context_state(self) -> str:
        """One of ``disabled``, ``pending``, ``loading``, ``ready``, ``unavailable``."""
        if not self._graph_path.is_file():
            return "disabled"
        if self._graph is None:
            return "pending"
        return self._graph.state

    def load_graph_context(self, timeout: Optional[float] = None) -> bool:
        """Build the index synchronously (warm-up hooks and tests)."""
        self.ensure_graph_context()
        if self._graph is None:
            return False
        return self._graph.wait(timeout)

    def predict_proba_for_accounts(self, accounts: Sequence[str]) -> Dict[str, float]:
        """Score transactions with the neighbours visible at their own time step.

        Returns only the ids the model graph knows about; an empty mapping means
        the caller should fall back to the rule path.
        """
        self.ensure_graph_context()
        if self._graph is None or self._graph.state != "ready":
            return {}
        return self._graph.probabilities_for(accounts)


def get_probability_model(
    checkpoint_path: Optional[str | os.PathLike] = None,
) -> Optional[HTGNNProbabilityModel]:
    """Return a cached model for the configured checkpoint, or None."""
    path = checkpoint_path or os.environ.get(CHECKPOINT_ENV_VAR) or DEFAULT_CHECKPOINT
    resolved = Path(path)
    if not resolved.is_file():
        logger.info(
            f"No HTGNN checkpoint at {resolved}; using rule-based scoring",
            event_type="model_checkpoint_missing",
        )
        return None

    key = str(resolved.resolve())
    with _CACHE_LOCK:
        cached = _MODEL_CACHE.get(key)
        if cached is not None:
            return cached
        model = HTGNNProbabilityModel(resolved)
        if not model.is_available():
            # Do not cache a broken checkpoint: a fixed artifact or key should
            # be picked up on the next request without a restart.
            logger.warning(
                f"HTGNN checkpoint {resolved} could not be loaded; using rule-based scoring",
                event_type="model_checkpoint_load_failed",
                metadata={"error": str(model.load_error)},
            )
            return None
        _MODEL_CACHE[key] = model
        return model


def reset_probability_model_cache() -> None:
    """Drop cached models (used by tests and after key rotation)."""
    with _CACHE_LOCK:
        _MODEL_CACHE.clear()
