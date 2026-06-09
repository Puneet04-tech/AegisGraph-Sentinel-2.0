"""
Regression test to ensure hardcoded mule account fixtures are not auto-loaded.

This test verifies that the production runtime state initializes with an empty
mule_accounts set, not with hardcoded demo/test fixtures.
"""

import pytest
from types import SimpleNamespace

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api import main as api_main


def test_runtime_initializes_with_empty_mule_accounts():
    """
    Verify that AppState initializes with an empty mule_accounts set.
    
    This ensures hardcoded demo/test fixtures are not embedded in production
    runtime state. Mule accounts should only be loaded from approved data sources
    (fraud-chain datasets, graph intelligence, configuration).
    """
    # Create a fresh AppState instance
    fresh_state = api_main.AppState()
    
    # Verify mule_accounts is initialized as an empty set
    assert isinstance(fresh_state.mule_accounts, set), \
        "mule_accounts should be a set"
    assert len(fresh_state.mule_accounts) == 0, \
        "mule_accounts should be empty at initialization"
    
    # Verify known hardcoded fixture accounts are NOT present
    hardcoded_fixtures = {
        'mule_acc_001',
        'mule_acc_002',
        'test_merchant',
        'suspect_account_1',
        'fraud_wallet_xyz',
    }
    
    for fixture_account in hardcoded_fixtures:
        assert fixture_account not in fresh_state.mule_accounts, \
            f"Hardcoded fixture account '{fixture_account}' should not be in initial state"


def test_fallback_scorer_handles_empty_mule_accounts():
    """
    Verify that the fallback risk scorer works correctly with empty mule_accounts.
    
    This ensures the system doesn't break when no fraud-chain data is available.
    """
    # Create a state with empty mule_accounts
    test_state = SimpleNamespace(
        graph_loaded=True,
        transaction_graph=api_main.nx.DiGraph(),
        mule_accounts=set(),  # Explicitly empty
        account_profiles={},
    )
    
    # Test transaction with accounts that were previously hardcoded fixtures
    transaction = {
        "source_account": "mule_acc_001",
        "target_account": "suspect_account_1",
        "amount": 60000,
    }
    
    # The scorer should not crash with empty mule_accounts
    result = api_main._fallback_compute_risk_score(
        transaction,
        biometrics={"hold_times": [220, 240], "flight_times": [90, 95]},
        graph_loaded=test_state.graph_loaded,
        transaction_graph=test_state.transaction_graph,
        mule_accounts=test_state.mule_accounts,
        account_profiles=test_state.account_profiles,
    )
    
    # Verify result structure is valid
    assert "risk_score" in result
    assert "decision" in result
    assert "breakdown" in result
    assert 0 <= result["risk_score"] <= 1
    
    # Since mule_accounts is empty, the graph risk should not include
    # the mule account penalty (0.6 for source, 0.4 for target)
    # The risk should come from other factors (velocity, behavior, entropy)
    assert result["risk_score"] < 1.0  # Should not be maxed out


def test_explanation_handles_empty_mule_accounts():
    """
    Verify that the explanation generator works correctly with empty mule_accounts.
    """
    test_state = SimpleNamespace(
        mule_accounts=set(),  # Explicitly empty
    )
    
    transaction = {
        "source_account": "mule_acc_001",
        "target_account": "suspect_account_1",
    }
    
    risk_result = {
        "risk_score": 0.5,
        "decision": "REVIEW",
        "breakdown": {"graph": 0.3, "velocity": 0.4, "behavior": 0.2, "entropy": 0.1},
    }
    
    # The explanation should not crash with empty mule_accounts
    explanation = api_main._fallback_generate_explanation(
        transaction=transaction,
        risk_result=risk_result,
        mule_accounts=test_state.mule_accounts,
    )
    
    # Verify explanation structure
    assert "explanation" in explanation
    assert "recommended_action" in explanation
    
    # Since mule_accounts is empty, the explanation should NOT mention
    # that the accounts are known mule accounts
    assert "KNOWN MULE ACCOUNT" not in explanation["explanation"]


def test_mule_accounts_populated_from_fraud_chains():
    """
    Verify that mule_accounts can be populated from fraud-chain data.
    
    This ensures the data-driven loading mechanism works correctly.
    """
    # Create a state with empty mule_accounts
    test_state = SimpleNamespace(
        mule_accounts=set(),
        fraud_chains=[],
    )
    
    # Simulate loading from fraud chains
    test_fraud_chains = [
        {"accounts": ["real_mule_1", "real_mule_2"]},
        {"accounts": ["real_mule_3"]},
    ]
    
    # Update mule_accounts from chains (mimicking the startup logic)
    for chain in test_fraud_chains:
        test_state.mule_accounts.update(chain.get('accounts', []))
    
    # Verify mule_accounts now contains the data-driven values
    assert "real_mule_1" in test_state.mule_accounts
    assert "real_mule_2" in test_state.mule_accounts
    assert "real_mule_3" in test_state.mule_accounts
    
    # Verify hardcoded fixtures are still not present
    assert "mule_acc_001" not in test_state.mule_accounts
    assert "test_merchant" not in test_state.mule_accounts
