"""
Setup script for AegisGraph Sentinel 2.0

This script helps set up the environment and verify installation
"""

import sys
import subprocess
from pathlib import Path
import importlib.util


def check_python_version():
    """Check if Python version is compatible"""
    print("Checking Python version...")
    if sys.version_info < (3, 9):
        print("❌ Python 3.9+ is required")
        print(f"   Your version: {sys.version}")
        return False
    print(f"✓ Python {sys.version.split()[0]}")
    return True


def check_dependencies():
    """Check if required packages can be imported"""
    print("\nChecking dependencies...")
    
    required_packages = [
        'torch',
        'torch_geometric',
        'networkx',
        'numpy',
        'pandas',
        'fastapi',
        'uvicorn',
        'pydantic',
        'yaml',
    ]
    
    missing = []
    for package in required_packages:
        package_name = package.replace('_', '-')  # Handle torch_geometric
        spec = importlib.util.find_spec(package.replace('-', '_'))
        if spec is None:
            missing.append(package_name)
            print(f"❌ {package_name}")
        else:
            print(f"✓ {package_name}")
    
    if missing:
        print(f"\n⚠ Missing packages: {', '.join(missing)}")
        print("Install with: pip install " + " ".join(missing))
        return False
    
    return True


def create_directories():
    """Create necessary directories"""
    print("\nCreating directories...")
    
    directories = [
        'data/synthetic',
        'models',
        'logs',
        'notebooks',
    ]
    
    for directory in directories:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        print(f"✓ {directory}/")
    
    return True


def verify_config():
    """Verify configuration file exists"""
    print("\nVerifying configuration...")
    
    config_path = Path('config/config.yaml')
    if config_path.exists():
        print(f"✓ config/config.yaml found")
        return True
    else:
        print(f"❌ config/config.yaml not found")
        return False


def run_tests():
    """Run basic import tests"""
    print("\nRunning import tests...")
    
    try:
        from src.models.htgat import HTGAT
        print("✓ HTGAT model")
        
        from src.models.risk_model import FraudDetectionModel
        print("✓ FraudDetectionModel")
        
        from src.features.behavioral_biometrics import KeystrokeDynamicsAnalyzer
        print("✓ Behavioral biometrics")
        
        from src.inference.risk_scorer import RiskScorer
        print("✓ Risk scorer")
        
        from src.api.main import app
        print("✓ FastAPI app")
        
        return True
    except Exception as e:
        print(f"❌ Import error: {e}")
        return False


def main():
    """Main setup routine"""
    print("=" * 80)
    print("AegisGraph Sentinel 2.0 - Setup & Verification")
    print("=" * 80)
    
    steps = [
        ("Python version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Directories", create_directories),
        ("Configuration", verify_config),
        ("Import tests", run_tests),
    ]
    
    results = []
    for name, func in steps:
        try:
            success = func()
            results.append((name, success))
        except Exception as e:
            print(f"\n❌ Error in {name}: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 80)
    print("Setup Summary")
    print("=" * 80)
    
    all_passed = True
    for name, success in results:
        status = "✓" if success else "❌"
        print(f"{status} {name}")
        if not success:
            all_passed = False
    
    print("=" * 80)
    
    if all_passed:
        print("\n🎉 Setup successful! You're ready to use AegisGraph Sentinel 2.0")
        print("\nNext steps:")
        print("1. Generate synthetic data: python -m src.data.data_generator")
        print("2. Start API server: python -m src.api.main")
        print("3. Test API: python example_usage.py")
        print("\nDocumentation: http://localhost:8000/docs")
    else:
        print("\n⚠ Setup incomplete. Please resolve the issues above.")
        print("\nFor dependencies, run: pip install -r requirements.txt")
    
    print()


if __name__ == "__main__":
    main()
