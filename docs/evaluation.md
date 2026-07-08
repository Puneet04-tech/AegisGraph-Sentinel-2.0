# Evaluation Methodology

## Synthetic Data Evaluation (current default)

Metrics published in the README (96.8% Precision, 94.2% Recall, <200ms
Latency) are computed as follows:

1. Data is generated via `python -m src.data.data_generator`, which produces
   synthetic transaction graphs with labeled mule/non-mule accounts based on
   [describe the generator's assumptions here — e.g. Erdős–Rényi graph
   structure, hand-tuned fraud-ring density, etc. — check src/data/data_generator.py
   and fill this in accurately].
2. The dataset is split into train/validation/test sets (check the actual
   split ratio used, e.g. 70/15/15).
3. The HTGNN model is trained on the train split and evaluated on the held-out
   test split.

**Limitation:** Because the same generator defines both the training
distribution and the evaluation distribution, this setup cannot measure
generalization to real-world fraud patterns, which are more complex and
adversarial than a synthetic generator can capture.

## Real-World Benchmark Evaluation

To address this, we additionally evaluate on [PaySim](https://www.kaggle.com/datasets/ealaxi/paysim1),
a public synthetic mobile-money dataset built to mimic real transaction logs
from an African mobile money provider (chosen over IEEE-CIS because it
models person-to-person transfer/mule-style fraud rather than card
transactions, which is closer to this project's domain).

Results:

| Dataset | Precision | Recall | Notes |
|---|---|---|---|
| Synthetic (internal generator) | 96.8% | 94.2% | Reported in README |
| PaySim (real-world-derived) | *TBD — see below* | *TBD* | Run via `tests/test_paysim_benchmark.py` |

*(Fill in the TBD row once you've run the benchmark — see Step 3 below.)*