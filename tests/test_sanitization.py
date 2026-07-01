import sys
import os

# Add src to path so we can import from it easily
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.defense_grid.controller import get_defense_controller
from src.graph_analytics.service import get_graph_service

def test_threat_sanitization():
    print("\n--- Testing Threat Sanitization ---")
    controller = get_defense_controller()
    
    # 1. Valid threat
    valid_data = {
        "type": "MALWARE_DETECTED",
        "severity": "HIGH",
        "affected_entities": ["ENT_123"]
    }
    res = controller.process_threat(valid_data)
    print("Valid threat processed:", res.get("response_id") is not None)
    
    # 2. Missing type
    missing_type = {
        "severity": "HIGH",
        "affected_entities": ["ENT_123"]
    }
    res = controller.process_threat(missing_type)
    print("Missing type caught:", res.get("status") == "REJECTED")
    
    # 3. Invalid entities type
    invalid_entities = {
        "type": "MALWARE_DETECTED",
        "affected_entities": "Just a string, not a list"
    }
    res = controller.process_threat(invalid_entities)
    print("Invalid entities gracefully handled:", res.get("response_id") is not None)
    
def test_graph_error_isolation():
    print("\n--- Testing Graph Error Isolation ---")
    service = get_graph_service()
    
    # Intentionally trigger an error by passing a None entity ID which is likely to fail in deeper analytics
    print("Calling analyze_paths with None targets...")
    res = service.analyze_paths(None, None)
    print("Analyze paths returned safely without crashing:", res is None)

if __name__ == "__main__":
    test_threat_sanitization()
    test_graph_error_isolation()
