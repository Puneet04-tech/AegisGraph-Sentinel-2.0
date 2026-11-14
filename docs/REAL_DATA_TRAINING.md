# Training on Real Data (Elliptic Bitcoin)

The synthetic generator is useful for wiring and smoke tests, but its labels are
invented. This pipeline trains the same `AegisHTGNN` on a **real, public,
labelled fraud graph**: the [Elliptic Bitcoin dataset](https://www.kaggle.com/datasets/ellipticco/elliptic-data-set)
(Weber et al., 2019, *Anti-Money Laundering in Bitcoin: Experimenting with
Graph Convolutional Networks for Financial Forensics*).

## Why this dataset

| Requirement | Elliptic |
|---|---|
| Real transactions with real labels | 203,769 Bitcoin transactions, 4,545 flagged illicit |
| Graph structure the HTGNN can consume | 234,355 directed payment edges |
| Time ordering (the "T" in HTGNN) | 49 time steps, ~2-week resolution |
| Redistribution | Public research dataset, no competition/auth gate |

Alternatives were rejected for concrete reasons: IEEE-CIS requires Kaggle
competition acceptance, DGraphFin's host was unreachable from this machine, and
T-Finance has no PyTorch Geometric loader in 2.6.1.

## Pipeline

```bash
# 1. Convert the raw CSVs into the HeteroData artifact (verifies column layout,
#    builds temporal masks, standardises features with training statistics only)
python -m src.data.real_data_adapter --raw-dir data/real/Elliptic/raw \
    --out data/real/elliptic_aegis.pt

# 2. Train with a strict temporal protocol
python -m src.training.real_train --graph data/real/elliptic_aegis.pt \
    --sha256 <digest from the report> --epochs 10 --window 10 --hidden 64 \
    --out models/htgnn_elliptic_v1.pt
```

Raw files expected in `--raw-dir` (the standard Elliptic release):

- `elliptic_txs_features.csv` — `txId, time step, f1..f165` (no header row, 167 columns)
- `elliptic_txs_classes.csv` — `txId, class` with `1` = illicit, `2` = licit, `unknown`
- `elliptic_txs_edgelist.csv` — `txId1, txId2` directed payment edges

## Artifact contract

`data/real/elliptic_aegis.pt` matches what the loader and model already consume:

```
data['account'].x            float [N, 165]   real transaction features
data['account'].y            float [N, 1]     illicit = 1, licit = 0
data['account'].time         long  [N]        real time step, 1..49
data['account'].train_mask   bool  [N]        labeled & time <= 34
data['account'].val_mask     bool  [N]        labeled & 35 <= time <= 41
data['account'].test_mask    bool  [N]        labeled & time >= 42
data['account','transacts','account'].edge_index    real payment edges
```

There is **no `device` node type**: Elliptic has no device/session entity, and
inventing one would be synthetic again. The loader derives its neighbour budget
from the edge types actually present, and the model accepts an account-only
graph.

## Temporal protocol

`src/training/real_train.py` differs from `src/training/train.py` on purpose:

1. **No future information.** For every time step `t` the model scores only the
   subgraph with `t - window <= time <= t` and is graded on labeled transactions
   from step `t`. A transaction can never aggregate over a payment that had not
   happened yet.
2. **No label noise.** Loss is computed only on labeled roots inside the split
   mask; the 157,205 `unknown` transactions never become silent negatives.
3. **Class imbalance.** `pos_weight` is set from the training split (~7.6).
4. **Best-epoch selection.** Validation AUC peaks early and then decays, so the
   checkpoint stores the best-validation epoch (never the test split).

`pyg-lib`/`torch-sparse` are not required: temporal leakage is prevented by
subgraph construction rather than by a sampler.

## Measured results

Reproduce with the command above (CPU, ~14 minutes, 10 epochs, hidden 64,
window 10, best epoch 5 restored):

| Split | Nodes | Illicit | ROC-AUC | PR-AUC (AP) | F1 @ 0.5 |
|---|---|---|---|---|---|
| Validation (steps 35–41) | 7,829 | 675 | **0.926** | 0.606 | 0.350 |
| Test (steps 42–49) | 8,841 | 408 | **0.807** | 0.270 | 0.160 |

Test F1 at the threshold chosen on validation (0.85) is **0.317**, versus
0.160 at a naive 0.5 cutoff — the ranking is much better than a fixed threshold
suggests.

Reference point from the same features and splits with a plain logistic
regression: validation AUC 0.898, test AUC 0.855. The graph model is therefore
*not* beating a linear baseline on this dataset yet; it does reach comparable
ranking quality while remaining the component that consumes graph structure.
Closing that gap (more hops, edge features such as amounts/timestamps, and
longer training) is the natural next step, not a solved problem.

## Serving the checkpoint

`src/inference/htgnn_probability.py` loads the encrypted checkpoint, rebuilds
`AegisHTGNN` from the metadata stored alongside the weights (head count and
depth are recovered from the weight shapes) and returns a fraud probability for
a feature vector. `AegisHTGNN`'s feature skip connection is what makes this
possible: a transaction with no neighbourhood is still scored from its own
features, and feature-only scoring reproduces the graph result (test AUC 0.809
vs 0.807 with edges).

The endpoint accepts the vector directly:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/fraud/check \
  -H "Content-Type: application/json" -H "X-API-Key: $AEGIS_API_KEY" \
  -d '{"transaction_id":"TXN1","source_account":"ACC-42","target_account":"ACC-43",
       "amount":2500,"timestamp":"2026-11-07T05:00:00Z",
       "account_features":[...165 values in training order...]}'
```

Responses carry `model_probability` and `model_source`. The model never becomes
a dependency of the fraud check:

| Situation | `model_probability` | `model_source` |
|---|---|---|
| Checkpoint loaded, features valid | probability | `htgnn` |
| No features, account is in the model graph | probability with neighbours | `htgnn` |
| No features, artifact has no graph context | `null` | `rules:no_graph_context` |
| No features, graph context still loading | `null` | `rules:graph_context_loading` |
| No features, account unknown to the model graph | `null` | `rules:account_not_in_model_graph` |
| No checkpoint / unreadable key | `null` | `rules:checkpoint_unavailable` |
| Wrong feature width, NaN, inference error | `null` | `rules:model_error` |
| Graph never loaded (fallback scorer) | probability or `null` | `htgnn` / `rules:*` |

The probability feeds the `graph` component (`max` of the rule signal and the
model, so a confident model can raise it but never lower a rule hit). Because
the graph component is 50% of the weighted score, a 0.92 probability alone would
score ~0.46 and be allowed, so a probability at or above the review/block
thresholds escalates the decision to at least that level — upward only.

Set `AEGIS_MODEL_CHECKPOINT` to point at a different artifact, and remember the
API process needs `MODEL_ENCRYPTION_KEY` in its environment (it is read from
`os.environ`, not from `.env` by the settings layer).

### Graph context: scoring a transaction with its neighbourhood

The artifact stores the original transaction ids (`account.tx_id`), so a check
that names a real transaction needs no feature vector at all:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/fraud/check \
  -H "Content-Type: application/json" -H "X-API-Key: $AEGIS_API_KEY" \
  -d '{"transaction_id":"TXN1","source_account":"164710543","target_account":"ACC-43",
       "amount":2500,"timestamp":"2026-11-07T05:00:00Z"}'
```

Serving resolves the id to its row, keeps the subgraph with
`t - window <= time <= t` (the same protocol training used), runs one forward
pass over that window and reads the transaction's probability out of it. No
future neighbour can leak in, because the window ends at the transaction's own
step.

- Every account id in the request (`source_account`, `target_account`) is looked
  up; the strongest match is used, so a mule on either side counts.
- Only the transaction's upstream `num_layers`-hop neighbourhood inside the
  window is scored (a few hundred nodes, ~25 ms), not the whole window. The
  network has no normalisation layers, so this reproduces a full-window pass
  exactly — verified against the whole-window reference on real data (max
  difference 1.2e-07). Repeated ids are cached.
- The artifact is loaded on a background thread the first time a lookup is
  attempted, so no request ever waits for the 200k-node file. Until it is ready
  the check reports `rules:graph_context_loading` and scores by rules.
- `AEGIS_MODEL_GRAPH` points at the artifact (default
  `data/real/elliptic_aegis.pt`); `AEGIS_MODEL_WINDOW` sets the window (default
  10, matching training).

An explicit `account_features` vector always takes precedence over the graph
lookup.

Making per-transaction scoring possible surfaced a latent bug: `HGTConv`
returned zeros for every node when a batch contained no edges, while the same
node took the `a_linears(0)` path when any other node in the batch had one. A
transaction's embedding therefore depended on its batch rather than on its own
neighbourhood, which also made isolated scoring disagree with windowed scoring
(0.826 vs 0.787 on one transaction). Empty batches now follow the same path as
populated ones.

## Known limitations

- **Temporal drift is real.** Validation AUC 0.926 falls to 0.807 on steps
  42–49; illicit behaviour changes after step 42 in this dataset.
- **One relation only.** Account→account payments; no device, merchant or
  KYC entities, so the heterogeneous machinery runs with a single edge type.
- **Graph context only knows the training graph.** A transaction id resolves
  to a row only if it was in the released Elliptic data; anything newer has no
  neighbours to score and needs either a feature vector or a rebuilt artifact.
- **Serving windows come from the artifact's own edges.** A live payment that
  is not an Elliptic transaction is never inserted into the graph here, so the
  model's view of "now" is the dataset's last known step for that id.
- **The real graph is still not the API's runtime graph.** The API loads
  `AEGIS_GRAPH_PATH` (the synthetic GraphML), while the checkpoint's artifact is
  a separate `.pt` file used only for features.
- **No streaming feed.** `src/data/kafka_consumer.py` is still a stub, so this
  model was trained offline from the released dataset.
