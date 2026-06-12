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
        
        # Stats
        self._stats = {
            "total_added": 0,
            "total_queries": 0,
            "total_evicted": 0,
        }
    
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
            
            # Store
            self._embeddings[case_id] = (embedding, metadata or {})
            self._stats["total_added"] += 1
            
            # LRU eviction: remove oldest if exceeds maxsize
            if len(self._embeddings) > self.maxsize:
                oldest_id, _ = self._embeddings.popitem(last=False)
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
        
        metadatas = metadatas or [{}] * len(case_ids)
        
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
            
            # Compute cosine similarity with all stored embeddings
            similarities = []
            for case_id, (stored_emb, metadata) in self._embeddings.items():
                sim = self._cosine_similarity(embedding, stored_emb)
                
                if sim >= threshold:
                    similarities.append(
                        SearchResult(
                            case_id=case_id,
                            similarity_score=float(sim),
                            metadata=metadata.copy(),
                        )
                    )
            
            # Sort by similarity (highest first)
            similarities.sort(key=lambda x: x.similarity_score, reverse=True)
            
            # Update stats
            self._stats["total_queries"] += 1
            
            return similarities[:k]
    
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
        results = []
        for embedding in embeddings:
            results.append(self.query(embedding, k=k, threshold=threshold))
        return results
    
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
                existing_metadata.update(metadata)
                self._embeddings[case_id] = (embedding, existing_metadata)
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
