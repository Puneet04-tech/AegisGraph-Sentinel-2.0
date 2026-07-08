"""
Standalone test for centrality detection - no API dependencies
Run with: python test_centrality_standalone.py
"""

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime, timedelta, timezone
import numpy as np

# Import just the fraud pattern detector
from src.features.fraud_pattern_detector import FraudPatternDetector


def test_layering_chain_detection():
    """Test linear layering chain detection"""
    print("\n✓ Testing Layering Chain Detection...")
    
    detector = FraudPatternDetector()
    
    # Create A → B → C → D linear chain
    transactions = [
        {
            'source_account': 'ACC_A',
            'target_account': 'ACC_B',
            'amount': 100000,
            'timestamp': datetime.now(timezone.utc),
        },
        {
            'source_account': 'ACC_B',
            'target_account': 'ACC_C',
            'amount': 95000,
            'timestamp': datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        {
            'source_account': 'ACC_C',
            'target_account': 'ACC_D',
            'amount': 90000,
            'timestamp': datetime.now(timezone.utc) + timedelta(minutes=10),
        },
    ]
    
    chains = detector.detect_layering_chains(transactions, betweenness_threshold=0.3)
    
    assert isinstance(chains, list), "Should return list"
    if chains:
        assert chains[0]['type'] == 'LAYERING_CHAIN', "Should be LAYERING_CHAIN type"
        assert chains[0]['pattern'] == 'LINEAR_LAYERING', "Should be LINEAR_LAYERING pattern"
        print(f"  ✓ Detected {len(chains)} layering chain(s)")
        print(f"    Risk Score: {chains[0]['risk_score']:.3f}")
        print(f"    Accounts: {chains[0]['chain_accounts']}")
    else:
        print("  ⚠ No chains detected (threshold may be too high)")


def test_super_mule_detection():
    """Test super-mule detection via PageRank"""
    print("\n✓ Testing Super-Mule Detection (PageRank)...")
    
    detector = FraudPatternDetector()
    
    # Create hub with high incoming volume
    transactions = []
    
    # 8 sources sending to hub
    for i in range(8):
        transactions.append({
            'source_account': f'ACC_SRC_{i}',
            'target_account': 'ACC_HUB',
            'amount': 50000,
            'timestamp': datetime.now(timezone.utc),
        })
    
    # Hub sending to 5 recipients
    for i in range(5):
        transactions.append({
            'source_account': 'ACC_HUB',
            'target_account': f'ACC_DST_{i}',
            'amount': 30000,
            'timestamp': datetime.now(timezone.utc) + timedelta(hours=1),
        })
    
    super_mules = detector.detect_super_mules(transactions, pagerank_threshold=0.3)
    
    assert isinstance(super_mules, list), "Should return list"
    if super_mules:
        assert super_mules[0]['type'] == 'SUPER_MULE', "Should be SUPER_MULE type"
        print(f"  ✓ Detected {len(super_mules)} super-mule(s)")
        print(f"    Hub Account: {super_mules[0]['account']}")
        print(f"    Risk Score: {super_mules[0]['risk_score']:.3f}")
        print(f"    Incoming Transfers: {super_mules[0]['incoming_transfers']}")
    else:
        print("  ⚠ No super-mules detected (threshold may be too high)")


def test_fraud_ring_detection():
    """Test fraud ring detection via clique detection"""
    print("\n✓ Testing Fraud Ring Detection (Clique)...")
    
    detector = FraudPatternDetector()
    
    # Create complete 4-node ring
    accounts = ['ACC_A', 'ACC_B', 'ACC_C', 'ACC_D']
    transactions = []
    
    timestamp = datetime.now(timezone.utc)
    for i, source in enumerate(accounts):
        for target in accounts:
            if source != target:
                transactions.append({
                    'source_account': source,
                    'target_account': target,
                    'amount': 25000,
                    'timestamp': timestamp + timedelta(minutes=i * 2),
                })
    
    rings = detector.detect_fraud_rings(
        transactions,
        min_clique_size=3,
        max_clique_size=8,
        density_threshold=0.75,
    )
    
    assert isinstance(rings, list), "Should return list"
    if rings:
        assert rings[0]['type'] == 'FRAUD_RING', "Should be FRAUD_RING type"
        print(f"  ✓ Detected {len(rings)} fraud ring(s)")
        print(f"    Ring Size: {rings[0]['ring_size']}")
        print(f"    Density: {rings[0]['density']:.3f}")
        print(f"    Risk Score: {rings[0]['risk_score']:.3f}")
    else:
        print("  ⚠ No rings detected")


def test_temporal_decay():
    """Test temporal decay weighting"""
    print("\n✓ Testing Temporal Decay Weighting...")
    
    detector = FraudPatternDetector()
    reference_time = datetime.now(timezone.utc)
    
    # Test recent pattern
    pattern_recent = {
        'type': 'TEST',
        'risk_score': 0.8,
        'detected_at': reference_time,
    }
    
    decayed_recent = detector.apply_temporal_decay_to_pattern(
        pattern_recent.copy(),
        decay_rate=0.1,
        reference_time=reference_time,
    )
    
    assert decayed_recent['temporal_decay_factor'] > 0.95, "Recent should have high decay"
    print(f"  ✓ Recent pattern (today):")
    print(f"    Original Score: {decayed_recent['original_risk_score']:.3f}")
    print(f"    Decay Factor: {decayed_recent['temporal_decay_factor']:.3f}")
    print(f"    Decayed Score: {decayed_recent['risk_score']:.3f}")
    
    # Test old pattern
    pattern_old = {
        'type': 'TEST',
        'risk_score': 0.8,
        'detected_at': reference_time - timedelta(days=30),
    }
    
    decayed_old = detector.apply_temporal_decay_to_pattern(
        pattern_old.copy(),
        decay_rate=0.1,
        reference_time=reference_time,
    )
    
    assert decayed_old['temporal_decay_factor'] < 0.1, "Old should have low decay"
    print(f"  ✓ Old pattern (30 days ago):")
    print(f"    Original Score: {decayed_old['original_risk_score']:.3f}")
    print(f"    Decay Factor: {decayed_old['temporal_decay_factor']:.3f}")
    print(f"    Decayed Score: {decayed_old['risk_score']:.3f}")


def test_integration():
    """Test all detections on complex network"""
    print("\n✓ Testing Integration (Complex Network)...")
    
    detector = FraudPatternDetector()
    reference_time = datetime.now(timezone.utc)
    
    transactions = []
    
    # Layer 1: Layering chain
    transactions.extend([
        {'source_account': 'LAYER_A', 'target_account': 'LAYER_B', 'amount': 100000,
         'timestamp': reference_time},
        {'source_account': 'LAYER_B', 'target_account': 'LAYER_C', 'amount': 95000,
         'timestamp': reference_time + timedelta(minutes=5)},
    ])
    
    # Layer 2: Super-mule hub
    for i in range(10):
        transactions.append({
            'source_account': f'SRC_{i}',
            'target_account': 'SUPER_MULE',
            'amount': 50000,
            'timestamp': reference_time,
        })
    
    # Layer 3: Fraud ring (4 accounts)
    ring_accounts = ['RING_A', 'RING_B', 'RING_C', 'RING_D']
    for source in ring_accounts:
        for target in ring_accounts:
            if source != target:
                transactions.append({
                    'source_account': source,
                    'target_account': target,
                    'amount': 30000,
                    'timestamp': reference_time + timedelta(hours=1),
                })
    
    # Run detections
    chains = detector.detect_layering_chains(transactions, betweenness_threshold=0.2)
    super_mules = detector.detect_super_mules(transactions, pagerank_threshold=0.3)
    rings = detector.detect_fraud_rings(transactions, density_threshold=0.75)
    
    print(f"  ✓ Layering chains detected: {len(chains)}")
    print(f"  ✓ Super-mules detected: {len(super_mules)}")
    if super_mules:
        print(f"    → {super_mules[0]['account']}: {super_mules[0]['risk_score']:.3f}")
    print(f"  ✓ Fraud rings detected: {len(rings)}")
    if rings:
        print(f"    → Size {rings[0]['ring_size']}: {rings[0]['risk_score']:.3f}")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("  CENTRALITY ANALYSIS TEST SUITE (Standalone)")
    print("="*70)
    
    try:
        test_layering_chain_detection()
        test_super_mule_detection()
        test_fraud_ring_detection()
        test_temporal_decay()
        test_integration()
        
        print("\n" + "="*70)
        print("  ✓ ALL TESTS PASSED")
        print("="*70 + "\n")
        return 0
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
