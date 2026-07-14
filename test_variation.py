import torch

from src.adversarial.attacks.feature import FeaturePerturbation
from src.adversarial.evaluator import build_synthetic_graph, evaluate_attack
from src.models.risk_model import FraudDetectionModel


def run_stress_test():
    print("Initializing memory stress test...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # 1. Initialize the GNN model
    model = FraudDetectionModel(
        node_feature_dim=32,
        hidden_dim=128,
        output_dim=64,
        num_node_types=5,
        num_edge_types=4,
        num_layers=2,
        heads=4,
        dropout=0.3,
    ).to(device)
    model.eval()

    # 2. Initialize attack
    attack = FeaturePerturbation()

    # 3. Simulate heavy validation / evaluation loops
    print("Running heavy batch evaluation loop to check memory stability...")
    initial_memory = 0
    if torch.cuda.is_available():
        initial_memory = torch.cuda.memory_allocated(device)
        print(f"Initial CUDA memory: {initial_memory / (1024 * 1024):.2f} MB")

    for i in range(1, 51):
        # Run adversarial evaluation
        _ = evaluate_attack(
            model=model,
            attack=attack,
            n_graphs=5,
            threshold=0.5,
            graph_builder=build_synthetic_graph,
        )

        if i % 10 == 0 and torch.cuda.is_available():
            current_memory = torch.cuda.memory_allocated(device)
            print(
                f"Iteration {i} - CUDA memory: "
                f"{current_memory / (1024 * 1024):.2f} MB"
            )
            # Assert memory does not leak/grow unbounded
            assert (
                current_memory <= initial_memory * 1.5
            ), "Memory leak detected!"

    print("Memory stress test completed successfully. Memory remains stable!")


if __name__ == "__main__":
    run_stress_test()
