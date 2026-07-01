import sys
import os
import pytest
from datetime import datetime

# Add src to path so we can import from it easily
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.graph_analytics.service import get_graph_service, reset_graph_service
from src.graph_analytics.store import reset_graph_store

@pytest.fixture(autouse=True)
def setup_teardown():
    reset_graph_service()
    reset_graph_store()
    yield
    reset_graph_service()
    reset_graph_store()


def test_lateral_movement_simulation():
    service = get_graph_service()
    
    # Create 5 nodes
    service.add_entity("node_a", "device", tags=["compromised"])
    service.add_entity("node_b", "device", tags=["regular"])
    service.add_entity("node_c", "device", tags=["high_value"])
    service.add_entity("node_d", "device", tags=["regular"])
    service.add_entity("node_e", "device", tags=["critical"])
    
    # Link them with varying weights
    service.link_entities("node_a", "node_b", weight=0.8) # Easy traversal
    service.link_entities("node_b", "node_c", weight=0.9) # Easy traversal (high value target)
    service.link_entities("node_c", "node_d", weight=0.6) # Moderate traversal
    service.link_entities("node_a", "node_e", weight=0.2) # Hard traversal (critical target)
    
    # Simulate lateral movement from node_a
    # Max steps = 2, min weight threshold = 0.5
    sim = service.simulate_lateral_movement("node_a", max_steps=2, min_weight_threshold=0.5)
    
    assert sim is not None
    assert sim.compromised_node_id == "node_a"
    
    # node_a -> node_b (0.8 > 0.5) -> node_c (0.9 > 0.5)
    # node_a -> node_e (0.2 < 0.5) so node_e is NOT reached
    # node_c -> node_d is step 3, which exceeds max_steps=2
    assert "node_a" in sim.vulnerable_nodes
    assert "node_b" in sim.vulnerable_nodes
    assert "node_c" in sim.vulnerable_nodes
    assert "node_e" not in sim.vulnerable_nodes
    assert "node_d" not in sim.vulnerable_nodes
    assert len(sim.vulnerable_nodes) == 3
    
    # Blast radius should be 3 / 5 = 60.0%
    assert sim.blast_radius_percentage == 60.0
    
    # High value assets at risk = 1 (node_c)
    assert sim.high_value_assets_at_risk == 1

if __name__ == "__main__":
    pytest.main(["-v", __file__])
