import torch

try:
    from torch_geometric.data import HeteroData
except ImportError as exc:  # pragma: no cover - depends on optional install
    raise ImportError(
        "synthetic_data_gen requires PyTorch Geometric, which is not part of "
        "requirements.txt because its install is platform and torch-version "
        "specific. Install it by following "
        "https://pytorch-geometric.readthedocs.io/en/latest/install/installation.html"
    ) from exc

def generate_synthetic_graph(
    num_accounts=1000, 
    num_devices=500, 
    num_transactions=5000, 
    num_logins=2000
):
    """
    Generates a synthetic HeteroData graph object for AegisGraph Sentinel 2.0.
    Simulates a financial network with Accounts, Devices, and their interactions.
    """
    data = HeteroData()

    print(f"Generating synthetic graph with {num_accounts} accounts and {num_transactions} transactions...")

    # ==========================================
    # 1. NODE FEATURES
    # ==========================================
    
    # Account Nodes: [account_age_days, balance_normalized, risk_score, kyc_status]
    account_features = torch.randn((num_accounts, 4), dtype=torch.float32)
    data['account'].x = account_features

    # Device Nodes: [device_age, os_risk_score, network_trust]
    device_features = torch.randn((num_devices, 3), dtype=torch.float32)
    data['device'].x = device_features

    # Mule Labels (0 = Legit, 1 = Mule Account) ~5% mules
    mule_labels = torch.bernoulli(torch.full((num_accounts,), 0.05)).to(torch.long)
    data['account'].y = mule_labels

    # ==========================================
    # 2. EDGE INDICES & FEATURES
    # ==========================================

    # Edge: Account -> Transacts -> Account
    src_accounts = torch.randint(0, num_accounts, (num_transactions,))
    dst_accounts = torch.randint(0, num_accounts, (num_transactions,))
    
    # Prevent self-loops
    mask = src_accounts != dst_accounts
    src_accounts = src_accounts[mask]
    dst_accounts = dst_accounts[mask]
    
    transaction_edge_index = torch.stack([src_accounts, dst_accounts], dim=0)
    data['account', 'transacts', 'account'].edge_index = transaction_edge_index

    # Transaction Features: [amount_normalized, hesitation_score, timestamp_offset]
    num_valid_transactions = transaction_edge_index.shape[1]
    transaction_features = torch.randn((num_valid_transactions, 3), dtype=torch.float32)
    data['account', 'transacts', 'account'].edge_attr = transaction_features

    # Edge: Device -> Logs_into -> Account
    src_devices = torch.randint(0, num_devices, (num_logins,))
    dst_login_accounts = torch.randint(0, num_accounts, (num_logins,))
    
    login_edge_index = torch.stack([src_devices, dst_login_accounts], dim=0)
    data['device', 'logs_into', 'account'].edge_index = login_edge_index

    # Login Features: [location_mismatch_score, time_of_day_risk]
    login_features = torch.randn((num_logins, 2), dtype=torch.float32)
    data['device', 'logs_into', 'account'].edge_attr = login_features

    print("Graph generation complete!")
    return data

if __name__ == "__main__":
    graph_data = generate_synthetic_graph()
    print("\n--- Graph Summary ---")
    print(graph_data)
    torch.save(graph_data, 'synthetic_aegis_graph.pt')
    print("\nSaved graph to 'synthetic_aegis_graph.pt'")