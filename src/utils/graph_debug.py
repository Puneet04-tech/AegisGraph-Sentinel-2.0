import os
import json
import logging
from datetime import datetime
from pathlib import Path

import networkx as nx

def print_graph_summary(graph: nx.Graph, max_nodes: int = 20, logger: logging.Logger = None):
    """
    Pretty-prints a terminal tree map / tabular view of node connections,
    risk scores, and directional edges for debugging.
    """
    def log(msg):
        if logger:
            logger.info(msg)
        else:
            print(msg)

    if not isinstance(graph, (nx.Graph, nx.DiGraph, nx.MultiDiGraph, nx.MultiGraph)):
        log(f"Invalid graph object: {type(graph)}")
        return

    log("="*60)
    log(f"--- AegisGraph Local State Inspector ---")
    log("="*60)
    log(f"Type:       {type(graph).__name__}")
    log(f"Nodes:      {graph.number_of_nodes()}")
    log(f"Edges:      {graph.number_of_edges()}")
    log(f"Directed:   {graph.is_directed()}")
    log("-"*60)
    
    log(f"--- NODE PREVIEW (Max {max_nodes}):")
    nodes_to_show = list(graph.nodes(data=True))[:max_nodes]
    for node, data in nodes_to_show:
        node_type = data.get("account_type") or data.get("type", "Unknown")
        risk = data.get("risk_score", "N/A")
        is_mule = data.get("is_mule", "N/A")
        log(f"  [{node}] Type: {node_type} | Risk: {risk} | Mule: {is_mule}")

    log("-"*60)
    log(f"--- EDGE PREVIEW (Max {max_nodes}):")
    edges_to_show = list(graph.edges(data=True))[:max_nodes]
    for u, v, data in edges_to_show:
        amount = data.get("amount", "N/A")
        mode = data.get("mode", "N/A")
        edge_type = data.get("type", "Transfer")
        if graph.is_directed():
            log(f"  {u} --[{edge_type} (Amt: {amount}, Mode: {mode})]--> {v}")
        else:
            log(f"  {u} --[{edge_type} (Amt: {amount}, Mode: {mode})]-- {v}")
    
    if graph.number_of_nodes() > max_nodes or graph.number_of_edges() > max_nodes:
        log("... (Output truncated for readability) ...")
        
    log("="*60)


def dump_graph_state(graph: nx.Graph, log_dir: str = "logs"):
    """
    Dumps the current runtime state of a graph (including active traversal history)
    into a localized, timestamped JSON snapshot file for post-mortem analysis.
    """
    if not isinstance(graph, (nx.Graph, nx.DiGraph, nx.MultiDiGraph, nx.MultiGraph)):
        raise ValueError(f"Expected a NetworkX graph, got {type(graph)}")

    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(log_dir, f"graph_debug_{timestamp}.json")

    # Serialize using NetworkX built-in node link data structure
    try:
        from networkx.readwrite import json_graph
        # Add edges="links" to prevent FutureWarnings in newer NetworkX versions
        data = json_graph.node_link_data(graph, edges="links")
        
        # Need to handle objects that aren't natively JSON serializable (like datetime)
        def default_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return str(obj)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=default_serializer)
            
        print(f"[SUCCESS] Successfully dumped graph state to {filepath}")
        return filepath
    except Exception as e:
        print(f"[ERROR] Failed to dump graph state: {str(e)}")
        return None
