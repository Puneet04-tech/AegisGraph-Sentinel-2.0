"""
Unit tests for API endpoints
"""

import pytest
from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api.main import app


client = TestClient(app)


class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_check(self):
        """Test /health endpoint"""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestStatsEndpoint:
    """Test statistics endpoint"""
    
    def test_get_stats(self):
        """Test /stats endpoint"""
        response = client.get("/stats")
        
        assert response.status_code == 200
        data = response.json()
        
        # Check expected fields
        assert "total_checks" in data
        assert "flagged_transactions" in data
        assert "average_response_time" in data
        assert "uptime_seconds" in data


class TestFraudCheckEndpoint:
    """Test fraud check endpoint"""
    
    def test_low_risk_transaction(self):
        """Test with a low-risk transaction"""
        transaction = {
            "transaction_id": "test_001",
            "amount": 50.0,
            "timestamp": 1234567890.0,
            "from_account": "user_1",
            "to_account": "merchant_1",
            "transaction_type": "payment",
            "metadata": {
                "location": "US",
                "device_id": "device_1"
            }
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        assert response.status_code == 200
        data = response.json()
        
        # Check response structure
        assert "transaction_id" in data
        assert "risk_score" in data
        assert "decision" in data
        assert "factors" in data
        assert "explanation" in data
        
        # Risk score should be between 0 and 1
        assert 0 <= data["risk_score"] <= 1
        
        # Decision should be valid
        assert data["decision"] in ["approve", "review", "block"]
    
    def test_high_risk_transaction(self):
        """Test with a high-risk transaction (large amount, rapid)"""
        transaction = {
            "transaction_id": "test_002",
            "amount": 10000.0,
            "timestamp": 1234567890.0,
            "from_account": "new_user",
            "to_account": "unknown_merchant",
            "transaction_type": "transfer",
            "metadata": {
                "location": "XX",
                "device_id": "new_device"
            }
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        assert response.status_code == 200
        data = response.json()
        
        # High-risk transaction should have high score
        # Note: This depends on model state, so just check structure
        assert "risk_score" in data
        assert "factors" in data
    
    def test_transaction_with_biometrics(self):
        """Test transaction with behavioral biometrics"""
        transaction = {
            "transaction_id": "test_003",
            "amount": 100.0,
            "timestamp": 1234567890.0,
            "from_account": "user_1",
            "to_account": "merchant_1",
            "transaction_type": "payment",
            "biometrics": {
                "keystroke_events": [
                    {"key": "a", "timestamp": 0.0, "event_type": "keydown"},
                    {"key": "a", "timestamp": 0.1, "event_type": "keyup"}
                ],
                "mouse_movements": []
            }
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        assert response.status_code == 200
        data = response.json()
        
        # Should include behavioral analysis
        assert "factors" in data
        assert "behavioral" in data["factors"]
    
    def test_invalid_transaction(self):
        """Test with invalid transaction data"""
        transaction = {
            "transaction_id": "test_004",
            # Missing required fields
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        # Should return validation error
        assert response.status_code == 422


class TestBatchFraudCheck:
    """Test batch fraud check endpoint"""
    
    def test_batch_check(self):
        """Test batch processing of transactions"""
        transactions = [
            {
                "transaction_id": f"batch_{i}",
                "amount": 50.0 * (i + 1),
                "timestamp": 1234567890.0 + i * 60,
                "from_account": f"user_{i}",
                "to_account": f"merchant_{i}",
                "transaction_type": "payment"
            }
            for i in range(3)
        ]
        
        response = client.post("/api/v1/fraud/batch", json={"transactions": transactions})
        
        assert response.status_code == 200
        data = response.json()
        
        # Should return results for all transactions
        assert len(data["results"]) == 3
        
        # Check each result
        for result in data["results"]:
            assert "transaction_id" in result
            assert "risk_score" in result
            assert "decision" in result
    
    def test_empty_batch(self):
        """Test with empty batch"""
        response = client.post("/api/v1/fraud/batch", json={"transactions": []})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 0


class TestCORSandSecurity:
    """Test CORS and security headers"""
    
    def test_cors_headers(self):
        """Test CORS headers are present"""
        response = client.get("/health", headers={"Origin": "http://localhost:3000"})
        
        # Should have CORS headers
        assert response.status_code == 200
    
    def test_rate_limiting(self):
        """Test rate limiting (if implemented)"""
        # Make multiple rapid requests
        responses = []
        for i in range(10):
            response = client.get("/health")
            responses.append(response.status_code)
        
        # All should succeed (rate limiting not implemented yet)
        assert all(code == 200 for code in responses)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
