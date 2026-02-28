"""
Test script for real-time innovation integration
Tests honeypot, blockchain, and keystroke stress detection
"""

import requests
import json
from datetime import datetime

API_BASE = "http://localhost:8000"

def test_high_risk_transaction():
    """Test transaction that should trigger honeypot and blockchain"""
    print("=" * 60)
    print("TEST 1: High-Risk Transaction (Mule-to-Mule Transfer)")
    print("=" * 60)
    
    payload = {
        "transaction_id": "TEST_HIGHRISK_001",
        "source_account": "ACC_MULE_0001",
        "target_account": "ACC_MULE_0002",
        "amount": 500000,
        "currency": "INR",
        "mode": "IMPS",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "biometrics": {
            "hold_times": [250, 300, 275, 280, 290],  # Slow/stressed typing
            "flight_times": [400, 380, 420, 410, 390]   # Hesitation between keys
        }
    }
    
    print(f"\n📤 Sending transaction: {payload['transaction_id']}")
    print(f"   From: {payload['source_account']} → To: {payload['target_account']}")
    print(f"   Amount: ₹{payload['amount']:,}")
    
    try:
        response = requests.post(
            f"{API_BASE}/api/v1/fraud/check",
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        result = response.json()
        
        print(f"\n✅ Response received:")
        print(f"   Risk Score: {result['risk_score']:.4f}")
        print(f"   Decision: {result['decision']}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Processing Time: {result['processing_time_ms']:.1f}ms")
        
        print(f"\n📊 Risk Breakdown:")
        for key, value in result['breakdown'].items():
            print(f"   {key}: {value:.4f}")
        
        print(f"\n💡 Explanation: {result['explanation']}")
        
        print(f"\n🚀 INNOVATION STATUS:")
        print(f"   🍯 Honeypot Activated: {result.get('honeypot_activated', False)}")
        if result.get('honeypot_id'):
            print(f"      Honeypot ID: {result['honeypot_id']}")
        
        print(f"   ⛓️  Blockchain Evidence: {result.get('blockchain_evidence_id', 'None')}")
        if result.get('blockchain_evidence_id'):
            print(f"      Evidence ID: {result['blockchain_evidence_id']}")
        
        print(f"   ⌨️  Behavioral Stress: {result.get('behavioral_stress_detected', False)}")
        
        # Check if honeypot was activated correctly
        if result['risk_score'] >= 0.90:
            if result.get('honeypot_activated'):
                print(f"\n✅ PASS: Honeypot activated for risk_score ≥ 0.90")
                if result['decision'] == 'ALLOW':
                    print(f"✅ PASS: Decision overridden to ALLOW (fake success)")
            else:
                print(f"\n⚠️  WARNING: Risk score {result['risk_score']:.4f} but honeypot not activated")
        
        # Check if blockchain evidence was sealed
        if result['decision'] in ['BLOCK', 'REVIEW'] or result.get('honeypot_activated'):
            if result.get('blockchain_evidence_id'):
                print(f"✅ PASS: Blockchain evidence sealed for {result['decision']} decision")
            else:
                print(f"⚠️  WARNING: High-risk transaction but no blockchain evidence")
        
        return result
        
    except requests.exceptions.RequestException as e:
        print(f"\n❌ ERROR: {e}")
        return None


def test_normal_transaction():
    """Test normal transaction that should not trigger innovations"""
    print("\n\n" + "=" * 60)
    print("TEST 2: Normal Transaction (Low Risk)")
    print("=" * 60)
    
    payload = {
        "transaction_id": "TEST_NORMAL_001",
        "source_account": "ACC_NORMAL_12345",
        "target_account": "ACC_NORMAL_67890",
        "amount": 5000,
        "currency": "INR",
        "mode": "UPI",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    print(f"\n📤 Sending transaction: {payload['transaction_id']}")
    print(f"   From: {payload['source_account']} → To: {payload['target_account']}")
    print(f"   Amount: ₹{payload['amount']:,}")
    
    try:
        response = requests.post(
            f"{API_BASE}/api/v1/fraud/check",
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        result = response.json()
        
        print(f"\n✅ Response received:")
        print(f"   Risk Score: {result['risk_score']:.4f}")
        print(f"   Decision: {result['decision']}")
        print(f"   Confidence: {result['confidence']:.2%}")
        
        print(f"\n🚀 INNOVATION STATUS:")
        print(f"   🍯 Honeypot Activated: {result.get('honeypot_activated', False)}")
        print(f"   ⛓️  Blockchain Evidence: {result.get('blockchain_evidence_id', 'None')}")
        print(f"   ⌨️  Behavioral Stress: {result.get('behavioral_stress_detected', False)}")
        
        if not result.get('honeypot_activated') and result['risk_score'] < 0.50:
            print(f"\n✅ PASS: Low-risk transaction, no innovations triggered")
        
        return result
        
    except requests.exceptions.RequestException as e:
        print(f"\n❌ ERROR: {e}")
        return None


def check_active_honeypots():
    """Check if honeypots appear in the active list"""
    print("\n\n" + "=" * 60)
    print("TEST 3: Active Honeypots Check")
    print("=" * 60)
    
    try:
        response = requests.get(f"{API_BASE}/api/v1/honeypot/active", timeout=10)
        response.raise_for_status()
        result = response.json()
        
        total = result.get('total_active', 0)
        print(f"\n📊 Active Honeypots: {total}")
        
        if total > 0:
            print(f"\n🍯 Honeypot Details:")
            for hp in result.get('active_honeypots', [])[:5]:  # Show first 5
                print(f"   ID: {hp['honeypot_id']}")
                print(f"   Transaction: {hp['transaction_id']}")
                print(f"   Amount: ₹{hp['amount']:,}")
                print(f"   Status: {hp['status']}")
                print(f"   Activated: {hp['activated_at']}")
                print()
        else:
            print("\n⚠️  No active honeypots found")
        
        return result
        
    except requests.exceptions.RequestException as e:
        print(f"\n❌ ERROR: {e}")
        None


def main():
    """Run all tests"""
    print("\n🧪 AEGISGRAPH SENTINEL 2.0 - REAL-TIME INNOVATION TESTS")
    print("=" * 60)
    
    # Test 1: High-risk transaction
    high_risk_result = test_high_risk_transaction()
    
    # Test 2: Normal transaction
    normal_result = test_normal_transaction()
    
    # Test 3: Check active honeypots
    honeypots = check_active_honeypots()
    
    # Summary
    print("\n\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    if high_risk_result:
        print(f"✅ Test 1 (High Risk): COMPLETED")
        print(f"   - Honeypot: {'ACTIVATED' if high_risk_result.get('honeypot_activated') else 'NOT ACTIVATED'}")
        print(f"   - Blockchain: {'SEALED' if high_risk_result.get('blockchain_evidence_id') else 'NOT SEALED'}")
        print(f"   - Behavioral Stress: {'DETECTED' if high_risk_result.get('behavioral_stress_detected') else 'NOT DETECTED'}")
    else:
        print(f"❌ Test 1 (High Risk): FAILED")
    
    if normal_result:
        print(f"✅ Test 2 (Normal): COMPLETED")
        print(f"   - Risk Score: {normal_result['risk_score']:.4f}")
        print(f"   - Decision: {normal_result['decision']}")
    else:
        print(f"❌ Test 2 (Normal): FAILED")
    
    if honeypots:
        print(f"✅ Test 3 (Honeypots): COMPLETED")
        print(f"   - Total Active: {honeypots.get('total_active',0)}")
    else:
        print(f"❌ Test 3 (Honeypots): FAILED")
    
    print("\n" + "=" * 60)
    print("🎯 Real-time Innovation Integration: {'WORKING ✅' if high_risk_result and high_risk_result.get('honeypot_activated') else 'NEEDS REVIEW ⚠️'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
