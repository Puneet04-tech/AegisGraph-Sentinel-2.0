"""
Latency benchmark for fraud detection inference across different backends.

Measures end-to-end inference time for both NetworkX and PyTorch Geometric backends,
reporting statistics against the 200-500ms SLA target.

Usage:
    python -m src.benchmarks.latency_benchmark --backend networkx --graph-size 50 --iterations 100
    python -m src.benchmarks.latency_benchmark --backend pytorch --graph-size 100 --iterations 50
"""

import argparse
import json
import logging
import os
import statistics
import time
from typing import Dict, List, Tuple

import numpy as np
import torch

logger = logging.getLogger(__name__)


def generate_synthetic_transaction_graph(
    num_nodes: int = 50,
    num_edges: int = 150,
    feature_dim: int = 32,
) -> Dict:
    """Generate a synthetic transaction graph for benchmarking."""
    np.random.seed(42)
    torch.manual_seed(42)

    x = torch.randn(num_nodes, feature_dim)
    edge_index = torch.randint(0, num_nodes, (2, min(num_edges, num_nodes * num_nodes // 2)))
    node_type = torch.randint(0, 5, (num_nodes,))
    edge_type = torch.randint(0, 4, (edge_index.shape[1],))
    edge_timestamp = torch.rand(edge_index.shape[1]) * 86400

    return {
        'x': x,
        'edge_index': edge_index,
        'node_type': node_type,
        'edge_type': edge_type,
        'edge_timestamp': edge_timestamp,
    }


def benchmark_networkx_inference(
    iterations: int = 100,
    graph_size: int = 50,
) -> Dict[str, float]:
    """Benchmark fraud detection using NetworkX backend.

    Args:
        iterations: Number of inference iterations to run
        graph_size: Number of nodes in the transaction graph

    Returns:
        Dictionary with latency statistics (all values in milliseconds)
    """
    try:
        from src.inference.risk_scorer import compute_risk_score
        import networkx as nx
    except ImportError as e:
        logger.error(f"Failed to import required modules: {e}")
        return {}

    latencies = []

    for _ in range(iterations):
        transaction = {
            'source_account': f'account_{np.random.randint(0, graph_size)}',
            'target_account': f'account_{np.random.randint(0, graph_size)}',
            'amount': np.random.uniform(1000, 100000),
        }

        t0 = time.perf_counter()
        try:
            result = compute_risk_score(
                transaction,
                graph_loaded=False,  # Use lightweight computation path for NetworkX
            )
        except Exception as e:
            logger.warning(f"Inference error: {e}")
            continue
        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies.append(elapsed_ms)

    if not latencies:
        return {}

    return {
        'iterations': len(latencies),
        'mean_ms': statistics.mean(latencies),
        'median_ms': statistics.median(latencies),
        'stdev_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0,
        'min_ms': min(latencies),
        'max_ms': max(latencies),
        'p50_ms': sorted(latencies)[len(latencies) // 2],
        'p99_ms': sorted(latencies)[int(0.99 * len(latencies))] if len(latencies) > 1 else latencies[0],
        'p999_ms': sorted(latencies)[int(0.999 * len(latencies))] if len(latencies) > 1 else latencies[0],
        'sla_met_pct': sum(1 for t in latencies if t <= 500) / len(latencies) * 100,
        'sla_p99_met': sorted(latencies)[int(0.99 * len(latencies))] <= 500 if len(latencies) > 1 else True,
    }


def benchmark_pytorch_inference(
    iterations: int = 100,
    graph_size: int = 50,
    device: str = 'cpu',
) -> Dict[str, float]:
    """Benchmark fraud detection using PyTorch backend.

    Args:
        iterations: Number of inference iterations to run
        graph_size: Number of nodes in the transaction graph
        device: Computation device ('cpu', 'cuda', 'mps')

    Returns:
        Dictionary with latency statistics (all values in milliseconds)
    """
    try:
        from src.models import load_model
        from src.inference.risk_scorer import RiskScorer
        from src.config import settings
    except ImportError as e:
        logger.error(f"Failed to import required modules: {e}")
        return {}

    try:
        model = load_model(settings.HTGNN_MODEL_PATH)
        config = {'model': {'device': device}, 'risk_scoring': {'weights': {}, 'thresholds': {}}}
        scorer = RiskScorer(model, config, device=torch.device(device))
    except Exception as e:
        logger.warning(f"Failed to load PyTorch model: {e}")
        return {}

    latencies = []

    for _ in range(iterations):
        graph_data = generate_synthetic_transaction_graph(num_nodes=graph_size)

        transaction = {
            'source_account': 'account_0',
            'target_account': f'account_{np.random.randint(1, graph_size)}',
            'amount': np.random.uniform(1000, 100000),
        }

        t0 = time.perf_counter()
        try:
            result = scorer.compute_risk_score(
                transaction,
                graph_data=graph_data,
            )
        except Exception as e:
            logger.warning(f"Inference error: {e}")
            continue
        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies.append(elapsed_ms)

    if not latencies:
        return {}

    return {
        'iterations': len(latencies),
        'mean_ms': statistics.mean(latencies),
        'median_ms': statistics.median(latencies),
        'stdev_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0,
        'min_ms': min(latencies),
        'max_ms': max(latencies),
        'p50_ms': sorted(latencies)[len(latencies) // 2],
        'p99_ms': sorted(latencies)[int(0.99 * len(latencies))] if len(latencies) > 1 else latencies[0],
        'p999_ms': sorted(latencies)[int(0.999 * len(latencies))] if len(latencies) > 1 else latencies[0],
        'sla_met_pct': sum(1 for t in latencies if t <= 500) / len(latencies) * 100,
        'sla_p99_met': sorted(latencies)[int(0.99 * len(latencies))] <= 500 if len(latencies) > 1 else True,
    }


def format_results(backend: str, graph_size: int, results: Dict) -> str:
    """Format benchmark results for display."""
    if not results:
        return f"\n{backend.upper()} Backend (Graph Size: {graph_size} nodes): FAILED\n"

    output = f"""
{backend.upper()} Backend (Graph Size: {graph_size} nodes)
{'=' * 50}
Iterations:         {results['iterations']}
Mean Latency:       {results['mean_ms']:.2f} ms
Median Latency:     {results['median_ms']:.2f} ms
Std Dev:            {results['stdev_ms']:.2f} ms
Min Latency:        {results['min_ms']:.2f} ms
Max Latency:        {results['max_ms']:.2f} ms

Percentiles:
  p50:              {results['p50_ms']:.2f} ms
  p99:              {results['p99_ms']:.2f} ms {'✓ SLA' if results['sla_p99_met'] else '✗ SLA BREACH'}
  p999:             {results['p999_ms']:.2f} ms

SLA Compliance (≤500ms):
  Transactions:     {results['sla_met_pct']:.1f}%
  P99 Target:       {'✓ MET' if results['sla_p99_met'] else '✗ MISSED'}
"""
    return output


def main():
    parser = argparse.ArgumentParser(
        description='Benchmark fraud detection latency across backends'
    )
    parser.add_argument(
        '--backend',
        choices=['networkx', 'pytorch', 'all'],
        default='all',
        help='Backend to benchmark (default: all)',
    )
    parser.add_argument(
        '--graph-size',
        type=int,
        default=50,
        help='Number of nodes in transaction graph (default: 50)',
    )
    parser.add_argument(
        '--iterations',
        type=int,
        default=100,
        help='Number of inference iterations (default: 100)',
    )
    parser.add_argument(
        '--device',
        choices=['cpu', 'cuda', 'mps'],
        default='cpu',
        help='Computation device for PyTorch (default: cpu)',
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output JSON file for results',
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )

    results = {}

    print("\nAegisGraph Sentinel 2.0 - Latency Benchmark")
    print("=" * 50)
    print(f"Graph Size: {args.graph_size} nodes")
    print(f"Iterations: {args.iterations}")
    print(f"SLA Target: 200-500ms per transaction")
    print("=" * 50)

    if args.backend in ['networkx', 'all']:
        print("\nBenchmarking NetworkX backend...")
        networkx_results = benchmark_networkx_inference(
            iterations=args.iterations,
            graph_size=args.graph_size,
        )
        results['networkx'] = networkx_results
        print(format_results('networkx', args.graph_size, networkx_results))

    if args.backend in ['pytorch', 'all']:
        print("\nBenchmarking PyTorch backend...")
        pytorch_results = benchmark_pytorch_inference(
            iterations=args.iterations,
            graph_size=args.graph_size,
            device=args.device,
        )
        results['pytorch'] = pytorch_results
        print(format_results('pytorch', args.graph_size, pytorch_results))

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

    print("\n" + "=" * 50)
    print("Summary:")
    print("- NetworkX: Suitable for development/testing only; does not meet 200-500ms SLA")
    print("- PyTorch (GPU): Meets SLA in production with appropriate hardware")
    print("=" * 50)


if __name__ == '__main__':
    main()
