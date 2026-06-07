# GNN Adversarial Robustness & Decoy Node Injection Report

**Generated:** 2026-06-02T18:56:31.817779+00:00

## Executive Summary

This report evaluates the resilience of the **HTGAT** GNN model under structural and feature attacks. Evaluation was performed across **20** graph snapshots using a decision threshold of **0.47**.

Specifically, we simulate a **Decoy Node Injection** attack where adversaries connect new dummy accounts to high-centrality hubs to dilute their GNN risk signals. We measure the drop in standard classification metrics (F1-Score, Precision, and Recall) to benchmark defensive robustness.

## Adversarial Simulation Benchmarks

### Attack Profile: `edge_addition`

| Budget | F1 (Clean → Attacked) | F1 Drop | Precision (Clean → Attacked) | Recall (Clean → Attacked) | Flip Rate |
|---|---|---|---|---|---|
| 1.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 5.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 10.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 25.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 50.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |


### Attack Profile: `edge_deletion`

| Budget | F1 (Clean → Attacked) | F1 Drop | Precision (Clean → Attacked) | Recall (Clean → Attacked) | Flip Rate |
|---|---|---|---|---|---|
| 1.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 5.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 10.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 25.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 50.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |


### Attack Profile: `node_injection`

| Budget | F1 (Clean → Attacked) | F1 Drop | Precision (Clean → Attacked) | Recall (Clean → Attacked) | Flip Rate |
|---|---|---|---|---|---|
| 1.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 5.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 10.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 25.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 50.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |


### Attack Profile: `feature_perturbation`

| Budget | F1 (Clean → Attacked) | F1 Drop | Precision (Clean → Attacked) | Recall (Clean → Attacked) | Flip Rate |
|---|---|---|---|---|---|
| 1.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 5.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 10.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 25.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 50.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |


### Attack Profile: `decoy_node_injection`

| Budget | F1 (Clean → Attacked) | F1 Drop | Precision (Clean → Attacked) | Recall (Clean → Attacked) | Flip Rate |
|---|---|---|---|---|---|
| 1.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 5.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 10.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 25.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |
| 50.00% | 0.4615 → 0.4615 | +0.0000 | 0.3000 → 0.3000 | 1.0000 → 1.0000 | 0.0% |

## Evasion & Dilution Attack Summary

1. **Decoy Node Injection Simulator**:
   - Targets high-degree accounts (centrality hubs) and injects dummy nodes to simulate transaction masking.
   - A high degradation in F1-score indicates the model is highly sensitive to topological changes that mask existing hubs.
2. **Structural Perturbations**:
   - Random edge addition or deletion alters the attention coefficients computed by the multi-head HTGAT layers, leading to flipped classification thresholds.

## Defensive Recommendations

- **Adversarial Training**: Augment the training loader with structural perturbations during batch preparation.
- **Centrality Hardening**: Incorporate topological invariant heuristics that are resilient to simple star-graph decoy attachments (e.g. core-decomposition prune-steps).
- **Feature-Structure Alignment**: Train the risk prediction head using a contrastive loss aligning raw transaction features with local subgraph topology to prevent topological evasion.
