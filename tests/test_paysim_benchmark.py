"""
Evaluates the trained HTGNN model against PaySim, a public real-world-derived
fraud dataset, to validate performance beyond synthetic data.

Dataset: https://www.kaggle.com/datasets/ealaxi/paysim1
Download paysim.csv manually and place it in data/paysim/paysim.csv
(not committed to the repo due to size — see docs/evaluation.md).
"""
import os
import pytest
import pandas as pd

PAYSIM_PATH = os.path.join("data", "paysim", "paysim.csv")

@pytest.mark.skipif(
    not os.path.exists(PAYSIM_PATH),
    reason="PaySim dataset not found locally. Download from Kaggle and place at data/paysim/paysim.csv"
)
def test_paysim_precision_recall():
    df = pd.read_csv(PAYSIM_PATH)

    # TODO: map PaySim columns to your model's expected input format
    # PaySim columns: step, type, amount, nameOrig, oldbalanceOrg,
    # newbalanceOrig, nameDest, oldbalanceDest, newbalanceDest, isFraud, isFlaggedFraud
    # You'll need to adapt this to however src/model or src/inference expects data.

    # from src.model import load_model, predict
    # model = load_model()
    # preds = predict(model, df)
    # precision = ...
    # recall = ...

    # assert precision > 0  # replace with real assertions once implemented
    pytest.skip("Implement mapping from PaySim schema to model input, then compute precision/recall")