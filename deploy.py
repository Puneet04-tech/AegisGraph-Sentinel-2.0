"""
Deployment script for AegisGraph Sentinel 2.0

This script helps deploy the fraud detection system:
1. Generates synthetic training data
2. Trains the model
3. Starts the API server
"""

import sys
import time
import subprocess
from pathlib import Path
import argparse


def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 80)
    print(text)
    print("=" * 80 + "\n")


def generate_data(num_accounts=1000, fraud_ratio=0.1):
    """Generate synthetic training data"""
    print_header("Step 1: Generating Synthetic Data")
    
    print(f"Creating dataset with {num_accounts} accounts...")
    print(f"Fraud ratio: {fraud_ratio:.1%}")
    
    try:
        from src.data.data_generator import SyntheticFraudGenerator
        
        generator = SyntheticFraudGenerator(
            num_accounts=num_accounts,
            fraud_ratio=fraud_ratio,
        )
        
        data = generator.generate()
        
        # Save to files
        output_dir = Path('data/synthetic')
        output_dir.mkdir(parents=True, exist_ok=True)
        
        data['transactions'].to_csv(output_dir / 'transactions.csv', index=False)
        data['accounts'].to_csv(output_dir / 'accounts.csv', index=False)
        
        print(f"✓ Generated {len(data['transactions'])} transactions")
        print(f"✓ Saved to data/synthetic/")
        
        return True
        
    except Exception as e:
        print(f"❌ Error generating data: {e}")
        return False


def train_model(epochs=10):
    """Train the fraud detection model"""
    print_header("Step 2: Training Model")
    
    print(f"Training for {epochs} epochs...")
    print("This may take several minutes...")
    
    try:
        # Run training script
        result = subprocess.run(
            [sys.executable, "example_training.py"],
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        if result.returncode == 0:
            print("✓ Model training completed")
            print("\nTraining output:")
            print(result.stdout[-500:])  # Last 500 chars
            return True
        else:
            print(f"❌ Training failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Training timed out (> 10 minutes)")
        return False
    except Exception as e:
        print(f"❌ Error training model: {e}")
        return False


def start_api_server(host="0.0.0.0", port=8000):
    """Start the FastAPI server"""
    print_header("Step 3: Starting API Server")
    
    print(f"Starting server at http://{host}:{port}")
    print("Press Ctrl+C to stop")
    print("\nEndpoints:")
    print(f"  - Health check: http://localhost:{port}/health")
    print(f"  - Documentation: http://localhost:{port}/docs")
    print(f"  - Fraud check: http://localhost:{port}/api/v1/fraud/check")
    
    try:
        subprocess.run([
            sys.executable, "-m", "uvicorn",
            "src.api.main:app",
            "--host", host,
            "--port", str(port),
            "--reload"
        ])
        
    except KeyboardInterrupt:
        print("\n\n✓ Server stopped")
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")


def quick_test():
    """Run quick API test"""
    print_header("Quick API Test")
    
    print("Testing API endpoints...")
    
    try:
        import requests
        
        # Test health
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✓ Health check passed")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
        
        # Test fraud check
        test_transaction = {
            "transaction_id": "test_001",
            "amount": 100.0,
            "timestamp": time.time(),
            "from_account": "test_user",
            "to_account": "test_merchant",
            "transaction_type": "payment"
        }
        
        response = requests.post(
            "http://localhost:8000/api/v1/fraud/check",
            json=test_transaction,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Fraud check passed")
            print(f"  Risk score: {data['risk_score']:.3f}")
            print(f"  Decision: {data['decision']}")
            return True
        else:
            print(f"❌ Fraud check failed: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to API (is it running?)")
        return False
    except Exception as e:
        print(f"❌ Test error: {e}")
        return False


def main():
    """Main deployment routine"""
    parser = argparse.ArgumentParser(
        description="Deploy AegisGraph Sentinel 2.0"
    )
    
    parser.add_argument(
        '--mode',
        choices=['full', 'data', 'train', 'serve', 'test'],
        default='full',
        help='Deployment mode'
    )
    
    parser.add_argument(
        '--accounts',
        type=int,
        default=1000,
        help='Number of accounts for synthetic data'
    )
    
    parser.add_argument(
        '--epochs',
        type=int,
        default=10,
        help='Number of training epochs'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='API server port'
    )
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("AegisGraph Sentinel 2.0 - Deployment")
    print("=" * 80)
    
    if args.mode in ['full', 'data']:
        if not generate_data(args.accounts):
            print("\n⚠ Data generation failed. Continuing anyway...")
    
    if args.mode in ['full', 'train']:
        if not train_model(args.epochs):
            print("\n⚠ Training failed. You can still run the API with random weights.")
    
    if args.mode in ['full', 'serve']:
        start_api_server(port=args.port)
    
    if args.mode == 'test':
        quick_test()


if __name__ == "__main__":
    main()
