import pytest
from src.utils.helpers import validate_dataset_splits


def test_valid_dataset_splits():
    config = {
        "data": {
            "train_split": 0.70,
            "val_split": 0.15,
            "test_split": 0.15,
        }
    }

    assert validate_dataset_splits(config) == []


def test_invalid_dataset_splits():
    config = {
        "data": {
            "train_split": 0.70,
            "val_split": 0.20,
            "test_split": 0.20,
        }
    }

    assert len(validate_dataset_splits(config)) > 0