"""
Example: Testing the AegisGraph Sentinel API

This script demonstrates how to use the fraud detection API
"""

import requests
import json
from datetime import datetime


# API endpoint
API_URL = "http://localhost:8000"


def check_transaction(transaction_data):
    """Check a single transaction"""
    response = requests.post(
        f"{API_URL}/api/v1/fraud/check",
        json=transaction_data
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return None


def main():
    print("=" * 80)
    print("AegisGraph Sentinel 2.0 - API Testing")
    print("=" * 80)
    
    # Example 1: Low-risk transaction
    print("\n1. Testing low-risk transaction...")
    low_risk_txn = {
        "transaction_id": "TXN0000000001",
        "source_account": "ACC00000001",
        "target_account": "ACC00000002",
        "amount": 500.00,
        "currency": "INR",
        "mode": "UPI",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "device_id": "DEV001",
    }
    
    result = check_transaction(low_risk_txn)
    if result:
        print(f"   Risk Score: {result['risk_score']:.2%}")
        print(f"   Decision: {result['decision']}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Processing Time: {result['processing_time_ms']:.2f}ms")
    
    # Example 2: High-risk transaction with behavioral anomalies
    print("\n2. Testing high-risk transaction with stress indicators...")
    high_risk_txn = {
        "transaction_id": "TXN0000000002",
        "source_account": "ACC00000003",
        "target_account": "ACC00000004",
        "amount": 75000.00,
        "currency": "INR",
        "mode": "UPI",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "device_id": "DEV002",
        "biometrics": {
            "hold_times": [180, 220, 195, 240, 210],  # Slow, variable
            "flight_times": [350, 420, 380, 450]  # Long pauses
        }
    }
    
    result = check_transaction(high_risk_txn)
    if result:
        print(f"   Risk Score: {result['risk_score']:.2%}")
        print(f"   Decision: {result['decision']}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Processing Time: {result['processing_time_ms']:.2f}ms")
        print(f"\n   Breakdown:")
        for component, score in result['breakdown'].items():
            print(f"      {component}: {score:.2%}")
        print(f"\n   Explanation:\n{result['explanation'][:200]}...")
    
    # Example 3: Batch processing
    print("\n3. Testing batch processing...")
    batch_request = {
        "transactions": [low_risk_txn, high_risk_txn]
    }
    
    response = requests.post(
        f"{API_URL}/api/v1/fraud/batch",
        json=batch_request
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"   Total Processed: {result['total_processed']}")
        print(f"   Blocked: {result['total_blocked']}")
        print(f"   Review: {result['total_review']}")
        print(f"   Allowed: {result['total_allowed']}")
        print(f"   Processing Time: {result['processing_time_ms']:.2f}ms")
    
    # Get service stats
    print("\n4. Service Statistics...")
    response = requests.get(f"{API_URL}/stats")
    if response.status_code == 200:
        stats = response.json()
        print(f"   Total Requests: {stats['total_requests']}")
        print(f"   Decisions: {stats['decisions']}")
        print(f"   Avg Risk Score: {stats['avg_risk_score']:.2%}")
        print(f"   Avg Processing Time: {stats['avg_processing_time_ms']:.2f}ms")
    
    print("\n" + "=" * 80)
    print("Testing complete!")
    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Could not connect to API server")
        print("Please ensure the server is running:")
        print("   python -m src.api.main")
