import threading
from collections import defaultdict, deque

import networkx as nx
import numpy as np

from ..config import get_settings

# Optional Redis import for production scaling
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class LateralMovementDetector:
    """
    Detects MITRE ATT&CK TA0008 (Lateral Movement).
    Upgraded for multi-worker production environments using Redis state syncing,
    with a thread-safe in-memory fallback for local testing.
    """

    def __init__(
        self,
        history_size=10,
        std_multiplier=2.0,
        spike_multiplier=3.0,
        risk_penalty=0.25
    ):
        self.history_size = history_size
        self.std_multiplier = std_multiplier
        self.spike_multiplier = spike_multiplier
        self.risk_penalty = risk_penalty

        runtime_settings = get_settings()
        self.redis_url = runtime_settings.innovations.redis_url
        self.use_redis = REDIS_AVAILABLE and self.redis_url

        if self.use_redis:
            print("LateralMovementDetector: Connected to Redis Backend for multi-worker scaling.")
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
        else:
            print("LateralMovementDetector: Using Thread-Safe In-Memory Backend (Single Worker).")
            # In-memory fallbacks protected by a Mutex lock
            self._lock = threading.Lock()
            self.centrality_history = defaultdict(
                lambda: deque(maxlen=self.history_size)
            )
            self.active_graph = nx.DiGraph()

    def update_graph(self, src_account, dst_account):
        """Updates the network topology dynamically across all workers."""
        if self.use_redis:
            # Atomic cross-worker edge weight increment
            edge_key = f"aegis:edges:{src_account}"
            self.redis_client.hincrby(edge_key, dst_account, 1)
            # Track active nodes for fast sub-graph reconstruction
            self.redis_client.sadd("aegis:nodes", src_account, dst_account)
        else:
            # Thread-safe in-memory update
            with self._lock:
                if self.active_graph.has_edge(src_account, dst_account):
                    self.active_graph[src_account][dst_account]['weight'] += 1
                else:
                    self.active_graph.add_edge(src_account, dst_account, weight=1)

    def _get_approx_graph(self):
        """Reconstructs the active graph topology (Redis mode)."""
        if not self.use_redis:
            return self.active_graph

        G = nx.DiGraph()
        nodes = self.redis_client.smembers("aegis:nodes")
        
        for src in nodes:
            edges = self.redis_client.hgetall(f"aegis:edges:{src}")
            for dst, weight in edges.items():
                G.add_edge(src, dst, weight=float(weight))
        return G

    def _calculate_approx_centrality(self, account_id):
        """Calculates localized betweenness centrality safely."""
        if self.use_redis:
            G = self._get_approx_graph()
        else:
            with self._lock:
                G = self.active_graph.copy()

        num_nodes = G.number_of_nodes()
        if num_nodes < 3:
            return 0.0

        k_approx = min(50, num_nodes)
        centralities = nx.betweenness_centrality(
            G,
            k=k_approx,
            normalized=True,
            weight='weight'
        )
        return centralities.get(account_id, 0.0)

    def analyze_account(self, account_id):
        """Evaluates the account against its historical baseline across workers."""
        current_score = self._calculate_approx_centrality(account_id)

        # 1. Store and retrieve history safely
        if self.use_redis:
            history_key = f"aegis:history:{account_id}"
            self.redis_client.lpush(history_key, current_score)
            self.redis_client.ltrim(history_key, 0, self.history_size - 1)
            
            # Fetch and reverse so oldest is first
            history = [float(x) for x in self.redis_client.lrange(history_key, 0, -1)]
            history.reverse()
        else:
            with self._lock:
                history_deque = self.centrality_history[account_id]
                history_deque.append(current_score)
                history = list(history_deque)

        # 2. Evaluate Triggers
        if len(history) < 3:
            return 0.0, False

        baseline_mean = np.mean(history)
        baseline_std = np.std(history)

        threshold = baseline_mean + (self.std_multiplier * baseline_std)
        std_trigger = current_score > threshold
        mult_trigger = current_score > (self.spike_multiplier * baseline_mean)

        is_pivoting = False
        risk_added = 0.0

        if (std_trigger or mult_trigger) and current_score > 0.05:
            is_pivoting = True
            risk_added = self.risk_penalty

        return risk_added, is_pivoting


if __name__ == "__main__":
    detector = LateralMovementDetector()
    print("Initializing Distributed Lateral Movement Engine...")

    detector.update_graph("ACC_002", "ACC_001")
    detector.update_graph("ACC_001", "ACC_003")

    risk, flagged = detector.analyze_account("ACC_001")
    print(f"Risk Added: {risk} | Pivoting Detected: {flagged}")
