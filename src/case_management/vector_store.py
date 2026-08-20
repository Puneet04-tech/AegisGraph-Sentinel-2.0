"""
Vector Store for Case Embeddings

Provides thread-safe in-memory storage and similarity search for fraud case embeddings.
Uses cosine similarity for finding semantically similar cases.
"""

import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import numpy as np
from collections import OrderedDict


@dataclass
class SearchResult:
    """Result from vector similarity search."""
    case_id: str
    similarity_score: float  # Cosine similarity [0, 1]
    metadata: Dict


class VectorStore:
    """
    Thread-safe in-memory vector store with cosine similarity search.
    
    Uses an OrderedDict for efficient LRU eviction when size exceeds maxsize.
    Supports batch operations and configurable similarity thresholds.
    
    Args:
        embedding_dim: Dimension of embeddings (e.g., 768 for many models)
        maxsize: Maximum number of embeddings to store (LRU eviction after)
        similarity_threshold: Minimum similarity score to return (0-1)
    """
    
    def __init__(
        self,
        embedding_dim: int = 768,
        maxsize: int = 10000,
        similarity_threshold: float = 0.5,
    ):
        self.embedding_dim = embedding_dim
        self.maxsize = maxsize
        self.similarity_threshold = similarity_threshold
        
        # Thread-safe storage
        self._lock = threading.RLock()
        
        # OrderedDict for LRU eviction: case_id -> (embedding, metadata)
        self._embeddings: OrderedDict[str, Tuple[np.ndarray, Dict]] = OrderedDict()

        # Parallel matrix of L2-normalised copies, so a query is one BLAS
        # matrix-vector product instead of a Python loop over every entry.
        # Rows are pre-normalised because a stored vector's norm never changes
        # after insertion, so recomputing it per query was pure waste.
        # One row of headroom: add() inserts before evicting, so the store
        # transiently holds maxsize + 1 entries.
        capacity = max(1, maxsize) + 1
        self._matrix = np.zeros((capacity, embedding_dim), dtype=np.float32)
        self._row_of: Dict[str, int] = {}
        self._id_at: List[Optional[str]] = [None] * capacity
        self._free_rows: List[int] = []
        self._next_row = 0

        # Stats
        self._stats = {
            "total_added": 0,
            "total_queries": 0,
            "total_evicted": 0,
        }

    def _claim_row(self, case_id: str) -> int:
        """Return the matrix row for a case, allocating one if needed."""
        existing = self._row_of.get(case_id)
        if existing is not None:
            return existing

        if self._free_rows:
            row = self._free_rows.pop()
        elif self._next_row < self._matrix.shape[0]:
            row = self._next_row
            self._next_row += 1
        else:
            # Should not be reachable while eviction keeps size <= maxsize,
            # but growing beats silently dropping the embedding.
            row = self._matrix.shape[0]
            self._matrix = np.vstack(
                [self._matrix, np.zeros((1, self.embedding_dim), dtype=np.float32)]
            )
            self._id_at.append(None)
            self._next_row = row + 1

        self._row_of[case_id] = row
        self._id_at[row] = case_id
        return row

    def _release_row(self, case_id: str) -> None:
        """Return a case's matrix row to the free list."""
        row = self._row_of.pop(case_id, None)
        if row is None:
            return
        self._id_at[row] = None
        # Zeroed so a stale vector can never score against a later query even
        # if the row is somehow read before being rewritten.
        self._matrix[row].fill(0.0)
        self._free_rows.append(row)

    @staticmethod
    def _normalise(embedding: np.ndarray) -> np.ndarray:
        """Return a unit-length float32 copy, or zeros for a degenerate vector."""
        vector = np.asarray(embedding, dtype=np.float32)
        # Non-finite values would poison every subsequent dot product.
        if not np.all(np.isfinite(vector)):
            vector = np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)
        norm = float(np.linalg.norm(vector))
        if norm == 0.0:
            return np.zeros(vector.shape, dtype=np.float32)
        return vector / norm

    def _active_rows(self) -> np.ndarray:
        """Row indices currently holding a live embedding, in insertion order.

        Insertion order is preserved so equal-scoring results tie-break exactly
        as they did when the query walked the OrderedDict directly.
        """
        return np.fromiter(
            (self._row_of[case_id] for case_id in self._embeddings),
            dtype=np.int64,
            count=len(self._embeddings),
        )
    
    def add(
        self,
        case_id: str,
        embedding: np.ndarray,
        metadata: Optional[Dict] = None,
    ) -> None:
        """
        Add or update an embedding in the store.
        
        Args:
            case_id: Unique case identifier
            embedding: Vector embedding (shape: [embedding_dim])
            metadata: Optional metadata dict (case_date, priority, status, etc.)
        
        Raises:
            ValueError: If embedding dimension doesn't match
        """
        if embedding.shape[0] != self.embedding_dim:
            raise ValueError(
                f"Embedding dimension mismatch. Expected {self.embedding_dim}, "
                f"got {embedding.shape[0]}"
            )
        
        with self._lock:
            # If updating existing, move to end (mark as recently used)
            if case_id in self._embeddings:
                self._embeddings.move_to_end(case_id)
            
            # Store a copy of the metadata so caller-owned dicts and the
            # store never alias the same object. Without this, update_metadata
            # on one case mutates every case sharing that dict.
            self._embeddings[case_id] = (embedding, dict(metadata) if metadata else {})
            self._matrix[self._claim_row(case_id)] = self._normalise(embedding)
            self._stats["total_added"] += 1

            # LRU eviction: remove oldest if exceeds maxsize
            if len(self._embeddings) > self.maxsize:
                oldest_id, _ = self._embeddings.popitem(last=False)
                self._release_row(oldest_id)
                self._stats["total_evicted"] += 1
    
    def add_batch(
        self,
        case_ids: List[str],
        embeddings: np.ndarray,
        metadatas: Optional[List[Dict]] = None,
    ) -> None:
        """
        Batch add multiple embeddings.
        
        Args:
            case_ids: List of case identifiers
            embeddings: Array of shape [batch_size, embedding_dim]
            metadatas: Optional list of metadata dicts
        """
        if embeddings.shape[1] != self.embedding_dim:
            raise ValueError(
                f"Embedding dimension mismatch. Expected {self.embedding_dim}, "
                f"got {embeddings.shape[1]}"
            )
        
        if len(case_ids) != len(embeddings):
            raise ValueError(
                f"Number of case_ids ({len(case_ids)}) must match "
                f"embeddings batch size ({len(embeddings)})"
            )
        
        # Distinct dict per case; [{}] * n would alias every entry to the
        # same object (add() defensively copies, but the default should not
        # rely on that masking the aliasing).
        metadatas = metadatas or [{} for _ in case_ids]
        
        for case_id, embedding, metadata in zip(case_ids, embeddings, metadatas):
            self.add(case_id, embedding, metadata)
    
    def query(
        self,
        embedding: np.ndarray,
        k: int = 10,
        threshold: Optional[float] = None,
    ) -> List[SearchResult]:
        """
        Find top-k most similar embeddings using cosine similarity.
        
        Args:
            embedding: Query vector (shape: [embedding_dim])
            k: Number of results to return
            threshold: Override default similarity_threshold for this query
        
        Returns:
            List of SearchResult objects, sorted by similarity (highest first)
        
        Raises:
            ValueError: If store is empty or embedding dimension mismatches
        """
        if embedding.shape[0] != self.embedding_dim:
            raise ValueError(
                f"Embedding dimension mismatch. Expected {self.embedding_dim}, "
                f"got {embedding.shape[0]}"
            )
        
        with self._lock:
            if not self._embeddings:
                return []

            threshold = threshold if threshold is not None else self.similarity_threshold
            self._stats["total_queries"] += 1

            scores = self._score_all(embedding)
            return self._top_k(scores, k, threshold)

    def _score_all(self, embedding: np.ndarray) -> np.ndarray:
        """Cosine similarity against every live embedding, in insertion order.

        One matrix-vector product replaces the per-entry Python loop; both
        operands are unit vectors, so the dot product *is* the cosine.
        """
        query = self._normalise(embedding)
        rows = self._active_rows()
        if rows.size == 0:
            return np.empty(0, dtype=np.float32)

        scores = self._matrix[rows] @ query
        # Matches the clamping the per-pair helper applied, absorbing the
        # floating-point drift that can push a self-match fractionally past 1.
        return np.clip(scores, 0.0, 1.0)

    def _top_k(self, scores: np.ndarray, k: int, threshold: float) -> List[SearchResult]:
        """Select the k highest-scoring results at or above the threshold."""
        if scores.size == 0 or k <= 0:
            return []

        case_ids = list(self._embeddings.keys())
        candidates = np.flatnonzero(scores >= threshold)
        if candidates.size == 0:
            return []

        if candidates.size > k:
            # argpartition finds the top k without ordering the rest, which is
            # what makes this cheaper than sorting every match.
            top = candidates[np.argpartition(-scores[candidates], k - 1)[:k]]
        else:
            top = candidates

        # Ascending index order first, so that the descending sort by score is
        # stable and equal scores keep the insertion ordering the loop had.
        top = np.sort(top)
        order = np.argsort(-scores[top], kind="stable")

        results = []
        for position in top[order]:
            case_id = case_ids[position]
            _, metadata = self._embeddings[case_id]
            results.append(
                SearchResult(
                    case_id=case_id,
                    similarity_score=float(scores[position]),
                    metadata=metadata.copy(),
                )
            )
        return results
    
    def query_batch(
        self,
        embeddings: np.ndarray,
        k: int = 10,
        threshold: Optional[float] = None,
    ) -> List[List[SearchResult]]:
        """
        Batch query multiple embeddings.
        
        Args:
            embeddings: Array of shape [batch_size, embedding_dim]
            k: Number of results per query
            threshold: Override similarity threshold
        
        Returns:
            List of result lists, one per query embedding
        """
        if embeddings.ndim != 2 or embeddings.shape[1] != self.embedding_dim:
            raise ValueError(
                f"Embedding dimension mismatch. Expected [batch, {self.embedding_dim}], "
                f"got {tuple(embeddings.shape)}"
            )

        with self._lock:
            if not self._embeddings or embeddings.shape[0] == 0:
                return [[] for _ in range(embeddings.shape[0])]

            threshold = threshold if threshold is not None else self.similarity_threshold
            self._stats["total_queries"] += embeddings.shape[0]

            rows = self._active_rows()
            queries = np.stack([self._normalise(vector) for vector in embeddings])
            # A single [batch, dim] x [dim, size] product for the whole batch,
            # rather than one scan of the store per query vector.
            scores = np.clip(queries @ self._matrix[rows].T, 0.0, 1.0)

            return [self._top_k(row_scores, k, threshold) for row_scores in scores]
    
    def get(self, case_id: str) -> Optional[Tuple[np.ndarray, Dict]]:
        """
        Retrieve a specific embedding by case_id.
        
        Args:
            case_id: Case identifier
        
        Returns:
            Tuple of (embedding, metadata) or None if not found
        """
        with self._lock:
            if case_id in self._embeddings:
                embedding, metadata = self._embeddings[case_id]
                self._embeddings.move_to_end(case_id)  # Mark as recently used
                return embedding, metadata.copy()
            return None
    
    def remove(self, case_id: str) -> bool:
        """
        Remove an embedding from the store.
        
        Args:
            case_id: Case identifier to remove
        
        Returns:
            True if removed, False if not found
        """
        with self._lock:
            if case_id in self._embeddings:
                del self._embeddings[case_id]
                self._release_row(case_id)
                return True
            return False
    
    def update_metadata(self, case_id: str, metadata: Dict) -> bool:
        """
        Update metadata for an existing embedding.
        
        Args:
            case_id: Case identifier
            metadata: New metadata dict (merges with existing)
        
        Returns:
            True if updated, False if case_id not found
        """
        with self._lock:
            if case_id in self._embeddings:
                embedding, existing_metadata = self._embeddings[case_id]
                # Build a fresh dict instead of mutating in place so the
                # caller's input and any aliased metadata stay untouched.
                merged = {**existing_metadata, **metadata}
                self._embeddings[case_id] = (embedding, merged)
                return True
            return False
    
    def size(self) -> int:
        """Return number of embeddings currently stored."""
        with self._lock:
            return len(self._embeddings)
    
    def clear(self) -> None:
        """Clear all embeddings from store."""
        with self._lock:
            self._embeddings.clear()
            self._row_of.clear()
            self._free_rows.clear()
            self._id_at = [None] * self._matrix.shape[0]
            self._next_row = 0
            self._matrix.fill(0.0)
    
    def get_stats(self) -> Dict:
        """Return store statistics."""
        with self._lock:
            return {
                **self._stats,
                "current_size": len(self._embeddings),
                "total_cases": len(self._embeddings),
                "max_size": self.maxsize,
            }
    
    @staticmethod
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        """
        Compute cosine similarity between two vectors.
        
        Args:
            a: Vector 1 (shape: [dim])
            b: Vector 2 (shape: [dim])
        
        Returns:
            Cosine similarity score in [0, 1]
        """
        # Normalize vectors
        a_norm = np.linalg.norm(a)
        b_norm = np.linalg.norm(b)
        
        if a_norm == 0 or b_norm == 0:
            return 0.0
        
        a_normalized = a / a_norm
        b_normalized = b / b_norm
        
        # Dot product of normalized vectors
        similarity = np.dot(a_normalized, b_normalized)
        
        # Clamp to [0, 1] to handle floating point errors
        return float(np.clip(similarity, 0.0, 1.0))
