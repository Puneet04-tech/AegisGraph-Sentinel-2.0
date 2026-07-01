import os
import tempfile
import networkx as nx

from src.utils.graph_debug import print_graph_summary, dump_graph_state

def test_graph_debug_utility():
    # 1. Create a dummy graph
    G = nx.DiGraph()
    
    # Add Nodes
    G.add_node("ACC001", type="Account", is_mule=True, risk_score=0.95)
    G.add_node("ACC002", type="Account", is_mule=False, risk_score=0.10)
    G.add_node("DEV123", type="Device", fingerprint="xyz123")
    
    # Add Edges
    G.add_edge("ACC001", "ACC002", type="Transfer", amount=50000, mode="UPI")
    G.add_edge("DEV123", "ACC001", type="Login", success=True)
    
    # 2. Test print
    print("\n--- Testing print_graph_summary ---")
    print_graph_summary(G)
    
    # 3. Test dump
    print("\n--- Testing dump_graph_state ---")
    with tempfile.TemporaryDirectory() as temp_dir:
        filepath = dump_graph_state(G, log_dir=temp_dir)
        
        assert filepath is not None
        assert os.path.exists(filepath)
        
        # Verify JSON
        import json
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert "nodes" in data
            assert "links" in data
            assert len(data["nodes"]) == 3
            assert len(data["links"]) == 2
            print("Snapshot verified successfully.")

if __name__ == "__main__":
    test_graph_debug_utility()
