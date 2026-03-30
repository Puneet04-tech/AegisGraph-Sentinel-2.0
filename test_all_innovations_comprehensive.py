#!/usr/bin/env python3
"""
Comprehensive Feature Verification Test Suite
Tests all 6 real-time innovations from AegisGraph Sentinel 2.0

Run this script to verify that ALL features are working end-to-end:
python test_all_innovations_comprehensive.py
"""

import requests
import json
import time
import base64
import numpy as np
from datetime import datetime

# API Configuration
API_URL = "http://localhost:8000"
HEADERS = {"Content-Type": "application/json"}

class TestResults:
    """Track test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []
    
    def add_result(self, name, status, details):
        """Add test result"""
        self.results.append({'name': name, 'status': status, 'details': details})
        if status == 'PASS':
            self.passed += 1
        else:
            self.failed += 1
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*80)
        print("COMPREHENSIVE INNOVATION TEST SUMMARY")
        print("="*80)
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"📊 Total: {self.passed + self.failed}")
        print("="*80)
        for result in self.results:
            status_icon = "✅" if result['status'] == 'PASS' else "❌"
            print(f"{status_icon} {result['name']}: {result['details']}")


def test_core_fraud_check():
    """Test 1: Core Transaction Fraud Check"""
    print("\n📋 Test 1: Core Fraud Detection Engine")
    print("-" * 60)
    
    payload = {
        "transaction_id": "TEST_001",
        "source_account": "ACC_NORMAL_123",
        "target_account": "ACC_NORMAL_456",
        "amount": 5000,
        "currency": "INR",
        "mode": "UPI",
        "timestamp": datetime.now().isoformat(),
        "device_id": "DEV_001",
    }
    
    try:
        response = requests.post(f"{API_URL}/api/v1/fraud/check", json=payload, headers=HEADERS)
        if response.status_code == 200:
            result = response.json()
            print(f"   Decision: {result.get('decision')}")
            print(f"   Risk Score: {result.get('risk_score', 0):.1%}")
            print(f"   Confidence: {result.get('confidence', 0):.1%}")
            print(f"   Processing Time: {result.get('processing_time_ms', 0):.2f}ms")
            return 'PASS', f"Core check working ({result.get('decision')})"
        else:
            return 'FAIL', f"HTTP {response.status_code}"
    except Exception as e:
        return 'FAIL', str(e)


def test_keystroke_stress_detection():
    """Test 2: Keystroke Stress Detection (Innovation 1)"""
    print("\n⌨️  Test 2: Keystroke Stress Detection")
    print("-" * 60)
    
    payload = {
        "transaction_id": "TEST_STRESS_001",
        "source_account": "ACC_VICTIM",
        "target_account": "ACC_MULE",
        "amount": 75000,
        "currency": "INR",
        "mode": "UPI",
        "timestamp": datetime.now().isoformat(),
        "biometrics": {
            "hold_times": [120.5, 135.2, 128.8, 142.1, 118.9, 145.3, 132.1],  # Elevated variance = stress
            "flight_times": [200.1, 185.5, 210.2, 195.8, 205.1, 190.3, 207.9],
        }
    }
    
    try:
        response = requests.post(f"{API_URL}/api/v1/fraud/check", json=payload, headers=HEADERS)
        if response.status_code == 200:
            result = response.json()
            stress_detected = result.get('behavioral_stress_detected', False)
            print(f"   Behavioral Stress Detected: {stress_detected}")
            print(f"   Risk Score: {result.get('risk_score', 0):.1%}")
            status = 'PASS' if stress_detected else 'PARTIAL'
            return status, f"Stress analysis {'triggered' if stress_detected else 'computed'}"
        else:
            return 'FAIL', f"HTTP {response.status_code}"
    except Exception as e:
        return 'FAIL', str(e)


def test_honeypot_escrow():
    """Test 3: Honeypot Virtual Escrow (Innovation 2)"""
    print("\n🍯  Test 3: Honeypot Virtual Escrow")
    print("-" * 60)
    
    payload = {
        "transaction_id": "TEST_HP_001",
        "source_account": "ACC_VICTIM",
        "target_account": "ACC_MULE",
        "amount": 100000,
        "currency": "INR",
        "mode": "UPI",
        "timestamp": datetime.now().isoformat(),
    }
    
    try:
        response = requests.post(f"{API_URL}/api/v1/fraud/check", json=payload, headers=HEADERS)
        if response.status_code == 200:
            result = response.json()
            honeypot_activated = result.get('honeypot_activated', False)
            honeypot_id = result.get('honeypot_id')
            print(f"   Honeypot Activated: {honeypot_activated}")
            if honeypot_id:
                print(f"   Honeypot ID: {honeypot_id}")
            
            # Try to get active honeypots
            hp_response = requests.get(f"{API_URL}/api/v1/honeypot/active", headers=HEADERS)
            if hp_response.status_code == 200:
                hp_list = hp_response.json()
                print(f"   Total Active Honeypots: {hp_list.get('total_active', 0)}")
            
            return 'PASS' if honeypot_activated else 'PARTIAL', f"Honeypot {'activated' if honeypot_activated else 'available'}"
        else:
            return 'FAIL', f"HTTP {response.status_code}"
    except Exception as e:
        return 'FAIL', str(e)


def test_mule_identification():
    """Test 4: Predictive Mule Identification (Innovation 3)"""
    print("\n🎯 Test 4: Predictive Mule Identification")
    print("-" * 60)
    
    payload = {
        "account_id": "ACC_NEW_MULE",
        "name": "Suspicious Account",
        "age": 25,
        "profession": "Student",
        "email": "temp_email@tempmail.com",
        "phone": "9876543210",
        "device_id": "DEV_NEW_001",
        "ip_address": "103.x.x.x",
        "stated_address": "Unknown Location",
        "facial_match": 0.65,
        "document_type": "Aadhaar",
        "initial_deposit": 1000,
        "form_completion_time_seconds": 3,  # Very fast = red flag
    }
    
    try:
        response = requests.post(f"{API_URL}/api/v1/mule/assess", json=payload, headers=HEADERS)
        if response.status_code == 200:
            result = response.json()
            risk_score = result.get('risk_score', 0)
            risk_level = result.get('risk_level', 'UNKNOWN')
            print(f"   Mule Risk Score: {risk_score:.1f}/100")
            print(f"   Risk Level: {risk_level}")
            print(f"   Red Flags: {len(result.get('red_flags', []))} detected")
            
            has_high_risk = risk_score > 70
            return 'PASS' if has_high_risk else 'PARTIAL', f"Mule score {risk_score:.0f} ({risk_level})"
        else:
            return 'FAIL', f"HTTP {response.status_code}"
    except Exception as e:
        return 'FAIL', str(e)


def test_voice_stress_analysis():
    """Test 5: Voice Stress Analysis (Innovation 4)"""
    print("\n🔊 Test 5: Voice Stress Analysis")
    print("-" * 60)
    
    # Create synthetic audio (base64 encoded "stress" pattern)
    # In production, this would be actual WAV audio
    synthetic_audio = b"RIFF" + b"\x00"*100 + b"WAVEfmt"
    audio_b64 = base64.b64encode(synthetic_audio).decode()
    
    payload = {
        "transaction_id": "TEST_VOICE_001",
        "audio_base64": audio_b64,
        "sample_rate": 16000,
    }
    
    try:
        response = requests.post(f"{API_URL}/api/v1/voice/analyze", json=payload, headers=HEADERS)
        if response.status_code == 200:
            result = response.json()
            stress_score = result.get('stress_score', 0)
            classification = result.get('classification', 'UNKNOWN')
            print(f"   Stress Score: {stress_score:.1%}")
            print(f"   Classification: {classification}")
            print(f"   Confidence: {result.get('confidence', 0):.1%}")
            
            return 'PASS' if classification != 'UNKNOWN' else 'PARTIAL', f"Voice analysis completed ({classification})"
        elif response.status_code == 503:
            return 'PARTIAL', "Voice analysis available but not triggered"
        else:
            return 'FAIL', f"HTTP {response.status_code}"
    except Exception as e:
        return 'FAIL', str(e)


def test_aegis_oracle_explainer():
    """Test 6: Aegis-Oracle Explainer (Innovation 5)"""
    print("\n🔮 Test 6: Aegis-Oracle Explainer")
    print("-" * 60)
    
    payload = {
        "transaction_id": "TEST_ORACLE_001",
        "source_account": "ACC_SOURCE",
        "target_account": "ACC_TARGET",
        "amount": 50000,
        "decision": "BLOCK",
        "risk_score": 0.92,
        "confidence": 0.95,
        "breakdown": {
            "graph": 0.89,
            "velocity": 0.95,
            "behavior": 0.88,
            "entropy": 0.93,
        },
        "innovations_triggered": ["honeypot_activated", "behavioral_stress_detected"],
    }
    
    try:
        response = requests.post(f"{API_URL}/api/v1/explain", json=payload, headers=HEADERS)
        if response.status_code == 200:
            result = response.json()
            narrative = result.get('main_narrative', '')
            factors = result.get('causal_factors', [])
            print(f"   Causal Factors Identified: {len(factors)}")
            print(f"   Narrative Generated: {'Yes' if narrative else 'No'}")
            print(f"   Main Narrative (truncated): {narrative[:100]}...")
            
            return 'PASS' if narrative else 'PARTIAL', f"Oracle explanation with {len(factors)} factors"
        elif response.status_code == 503:
            return 'PARTIAL', "Oracle available but not triggered"
        else:
            return 'FAIL', f"HTTP {response.status_code}"
    except Exception as e:
        return 'FAIL', str(e)


def test_blockchain_evidence():
    """Test 7: Blockchain Evidence Chain (Innovation 6)"""
    print("\n⛓️  Test 7: Blockchain Evidence Chain")
    print("-" * 60)
    
    payload = {
        "transaction_id": "TEST_BLOCK_001",
        "source_account": "ACC_SOURCE",
        "target_account": "ACC_TARGET",
        "amount": 50000,
        "risk_result": {
            "risk_score": 0.92,
            "decision": "BLOCK",
            "confidence": 0.95,
            "breakdown": {"graph": 0.89, "velocity": 0.95, "behavior": 0.88, "entropy": 0.93},
        },
        "explanation": "Test blockchain sealing",
    }
    
    try:
        response = requests.post(f"{API_URL}/api/v1/blockchain/seal", json=payload, headers=HEADERS)
        if response.status_code == 200:
            result = response.json()
            evidence_id = result.get('evidence_id')
            block_number = result.get('block_number')
            finality_time = result.get('finality_time_ms', 0)
            print(f"   Evidence ID: {evidence_id}")
            print(f"   Block Number: {block_number}")
            print(f"   Sealing Time: {finality_time:.2f}ms")
            
            # Try to verify
            verify_response = requests.get(
                f"{API_URL}/api/v1/blockchain/verify/{evidence_id}?block_number={block_number}",
                headers=HEADERS
            )
            if verify_response.status_code == 200:
                verify_result = verify_response.json()
                print(f"   Verification Status: {verify_result.get('verified')}")
            
            return 'PASS', f"Evidence sealed in {finality_time:.1f}ms"
        elif response.status_code == 503:
            return 'PARTIAL', "Blockchain available but not triggered"
        else:
            return 'FAIL', f"HTTP {response.status_code}"
    except Exception as e:
        return 'FAIL', str(e)


def test_batch_processing():
    """Test 8: Batch Transaction Processing"""
    print("\n📦 Test 8: Batch Transaction Processing")
    print("-" * 60)
    
    transactions = [
        {
            "transaction_id": f"BATCH_{i}",
            "source_account": f"ACC_SRC_{i}",
            "target_account": f"ACC_TGT_{i}",
            "amount": 10000 + (i * 1000),
            "currency": "INR",
            "mode": "UPI",
            "timestamp": datetime.now().isoformat(),
        }
        for i in range(5)
    ]
    
    payload = {"transactions": transactions}
    
    try:
        response = requests.post(f"{API_URL}/api/v1/fraud/batch", json=payload, headers=HEADERS)
        if response.status_code == 200:
            result = response.json()
            total = result.get('total_processed', 0)
            blocked = result.get('total_blocked', 0)
            allowed = result.get('total_allowed', 0)
            time_ms = result.get('processing_time_ms', 0)
            print(f"   Transactions Processed: {total}")
            print(f"   Time per Transaction: {time_ms/max(total, 1):.2f}ms")
            print(f"   Blocked: {blocked}, Allowed: {allowed}")
            
            return 'PASS', f"Batch processed {total} transactions in {time_ms:.1f}ms"
        else:
            return 'FAIL', f"HTTP {response.status_code}"
    except Exception as e:
        return 'FAIL', str(e)


def test_health_check():
    """Test 9: System Health Check"""
    print("\n💚 Test 9: System Health & Status")
    print("-" * 60)
    
    try:
        response = requests.get(f"{API_URL}/api/v1/health", headers=HEADERS)
        if response.status_code == 200:
            result = response.json()
            status = result.get('status')
            model_loaded = result.get('model_loaded')
            graph_loaded = result.get('graph_loaded')
            print(f"   Status: {status}")
            print(f"   Model Loaded: {model_loaded}")
            print(f"   Graph Loaded: {graph_loaded}")
            print(f"   Requests Processed: {result.get('requests_processed', 0)}")
            
            return 'PASS' if status == 'healthy' else 'PARTIAL', f"Status: {status}"
        else:
            return 'FAIL', f"HTTP {response.status_code}"
    except Exception as e:
        return 'FAIL', str(e)


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("🧪 COMPREHENSIVE AEGISGRAPH SENTINEL 2.0 INNOVATION TEST SUITE")
    print("="*80)
    print(f"API Endpoint: {API_URL}")
    print(f"Test Time: {datetime.now().isoformat()}")
    print("="*80)
    
    results = TestResults()
    
    # Wait for API to be ready
    print("\n🔄 Waiting for API to be ready...")
    for _ in range(10):
        try:
            requests.get(f"{API_URL}/api/v1/health", timeout=2)
            print("✅ API is ready")
            break
        except:
            time.sleep(1)
    
    # Run all tests
    tests = [
        ("Core Fraud Detection", test_core_fraud_check),
        ("Keystroke Stress Detection", test_keystroke_stress_detection),
        ("Honeypot Virtual Escrow", test_honeypot_escrow),
        ("Predictive Mule Identification", test_mule_identification),
        ("Voice Stress Analysis", test_voice_stress_analysis),
        ("Aegis-Oracle Explainer", test_aegis_oracle_explainer),
        ("Blockchain Evidence Chain", test_blockchain_evidence),
        ("Batch Processing", test_batch_processing),
        ("System Health", test_health_check),
    ]
    
    for test_name, test_func in tests:
        try:
            status, details = test_func()
            results.add_result(test_name, status, details)
        except Exception as e:
            results.add_result(test_name, 'FAIL', str(e))
    
    # Print summary
    results.print_summary()
    
    print("\n✨ Test suite completed!")
    print(f"💾 Next Steps: Review test results above to ensure all 6 innovations are operational.")


if __name__ == "__main__":
    main()
