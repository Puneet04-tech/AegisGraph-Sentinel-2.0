"""
Dynamic Memory Batching & CUDA Eviction Evaluator Module.
Prevents PyTorch Out-Of-Memory (OOM) errors during graph evaluation runs by dynamically tuning
batch sizes and triggering CUDA memory cache evictions (#2591).
"""

import gc
from typing import Any, Callable, List, Optional


class DynamicBatchEvaluator:
    """
    Graph evaluator that manages dynamic batch sizes and memory cache eviction.
    """

    def __init__(
        self,
        initial_batch_size: int = 256,
        min_batch_size: int = 16,
        memory_threshold: float = 0.85,
    ):
        self.current_batch_size = initial_batch_size
        self.min_batch_size = min_batch_size
        self.memory_threshold = memory_threshold
        self.eviction_count = 0

    def evict_memory_cache(self) -> None:
        """Force Python garbage collection and CUDA cache eviction if PyTorch is available."""
        gc.collect()
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
                self.eviction_count += 1
        except ImportError:
            pass

    def reduce_batch_size(self) -> int:
        """Halve the current batch size until min_batch_size threshold."""
        self.current_batch_size = max(
            self.min_batch_size, self.current_batch_size // 2
        )
        self.evict_memory_cache()
        return self.current_batch_size

    def evaluate_batches(
        self, items: List[Any], eval_fn: Callable[[List[Any]], Any]
    ) -> List[Any]:
        """
        Evaluate items in dynamic batches, automatically recovering from simulated OOM errors.
        """
        results = []
        i = 0
        while i < len(items):
            batch = items[i : i + self.current_batch_size]
            try:
                batch_result = eval_fn(batch)
                results.append(batch_result)
                i += len(batch)
            except RuntimeError as err:
                if "out of memory" in str(err).lower() or "oom" in str(err).lower():
                    if self.current_batch_size <= self.min_batch_size:
                        self.evict_memory_cache()
                        raise err
                    self.reduce_batch_size()
                else:
                    raise err

        return results
