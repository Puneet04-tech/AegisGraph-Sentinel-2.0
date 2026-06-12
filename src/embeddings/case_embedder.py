import hashlib
from typing import Dict, List, Optional
import numpy as np
import logging

logger = logging.getLogger(__name__)

class CaseEmbedder:
    """
    Generate embeddings for fraud case explanations using google-generativeai.
    
    Features:
    - Caching of embeddings for performance
    - Batch embedding support
    - Graceful fallback to mock embeddings if API unavailable
    - Automatic text truncation for long explanations
    
    Args:
        model: Embedding model name (e.g., 'models/embedding-001')
        embedding_dim: Expected embedding dimension
        use_cache: Whether to cache embeddings
        max_text_length: Maximum text length before truncation
    """
    
    def __init__(
        self,
        model: str = "models/embedding-001",
        embedding_dim: int = 768,
        use_cache: bool = True,
        max_text_length: int = 10000,
    ):
        self.model = model
        self.embedding_dim = embedding_dim
        self.use_cache = use_cache
        self.max_text_length = max_text_length
        self._cache: Dict[str, np.ndarray] = {}
        
        # Try to import google-generativeai
        try:
            import os
            import google.generativeai as genai

            api_key = os.getenv("GOOGLE_API_KEY")

            if api_key:
                genai.configure(api_key=api_key)
                self.genai = genai
                self.client_available = True
                logger.info("google-generativeai client initialized")
            else:
                logger.info(
                    "GOOGLE_API_KEY not configured. Using deterministic mock embeddings."
                )
                self.genai = None
                self.client_available = False

        except ImportError:
            logger.warning(
                "google-generativeai not available; using mock embeddings."
            )
            self.genai = None
            self.client_available = False
    
    def embed_text(self, text: str) -> np.ndarray:
        """
        Generate embedding for a single text.
        
        Args:
            text: Input text (e.g., fraud explanation)
        
        Returns:
            Embedding vector (shape: [embedding_dim])
        """
        # Validate input
        if not text or not isinstance(text, str):
            logger.warning("Empty or invalid text for embedding, returning zero vector")
            return np.zeros(self.embedding_dim, dtype=np.float32)
        
        # Truncate if necessary
        text = text[:self.max_text_length]
        
        # Check cache
        if self.use_cache:
            text_hash = hashlib.sha256(text.encode()).hexdigest()
            if text_hash in self._cache:
                return self._cache[text_hash].copy()
        
        # Generate embedding
        embedding = self._generate_embedding(text)
        
        # Store in cache
        if self.use_cache:
            self._cache[text_hash] = embedding.copy()
        
        return embedding
    
    def embed_batch(self, texts: List[str]) -> np.ndarray:
        """
        Generate embeddings for multiple texts.
        
        Args:
            texts: List of input texts
        
        Returns:
            Array of embeddings (shape: [len(texts), embedding_dim])
        """
        embeddings = []
        for text in texts:
            embeddings.append(self.embed_text(text))
        
        return np.array(embeddings, dtype=np.float32)
    
    def embed_case_explanation(self, explanation_dict: Dict) -> np.ndarray:
        """
        Generate embedding from a fraud case explanation dict.
        
        Expected keys:
        - summary: Brief case summary
        - explanation: Detailed explanation
        - factors: Risk factors
        
        Args:
            explanation_dict: Fraud case explanation from Aegis-Oracle
        
        Returns:
            Embedding vector
        """
        # Extract and combine explanation components
        parts = []
        
        if "summary" in explanation_dict:
            parts.append(explanation_dict["summary"])
        
        if "explanation" in explanation_dict:
            parts.append(explanation_dict["explanation"])
        
        if "factors" in explanation_dict:
            factors = explanation_dict["factors"]
            if isinstance(factors, dict):
                factors_text = " ".join([f"{k}: {v}" for k, v in factors.items()])
            else:
                factors_text = str(factors)
            parts.append(factors_text)
        
        combined_text = " ".join(parts)
        return self.embed_text(combined_text)
    
    def _generate_embedding(self, text: str) -> np.ndarray:
        """
        Generate embedding using google-generativeai or mock.
        
        Args:
            text: Input text
        
        Returns:
            Embedding vector
        """
        if self.client_available and self.genai is not None:
            try:
                result = self.genai.embed_content(
                    model=self.model,
                    content=text,
                )
                embedding = np.array(result['embedding'], dtype=np.float32)
                
                if len(embedding) != self.embedding_dim:
                    logger.warning(
                        f"Embedding dimension mismatch: got {len(embedding)}, "
                        f"expected {self.embedding_dim}"
                    )
                
                return embedding
            except Exception as e:
                logger.error(f"Error generating embedding: {e}. Using mock embedding.")
                return self._mock_embedding(text)
        else:
            return self._mock_embedding(text)
    
    def _mock_embedding(self, text: str) -> np.ndarray:
        """
        Generate deterministic mock embedding (for testing/offline use).
        
        Creates a stable embedding from text hash so same text always
        produces same embedding.
        
        Args:
            text: Input text
        
        Returns:
            Mock embedding vector
        """
        # Use text hash as seed for reproducibility
        hash_bytes = hashlib.sha256(text.encode()).digest()
        seed = int.from_bytes(hash_bytes[:4], 'big')
        
        # Generate reproducible random vector
        rng = np.random.RandomState(seed)
        embedding = rng.randn(self.embedding_dim).astype(np.float32)
        
        # Normalize to unit vector
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        
        return embedding
    
    def get_cache_stats(self) -> Dict:
        return {
            "cache_size": len(self._cache),
            "cached_embeddings": len(self._cache),
            "cache_enabled": self.use_cache,
        }
    
    def clear_cache(self) -> None:
        """Clear embedding cache."""
        self._cache.clear()
        logger.info("Embedding cache cleared")


# Global embedder instance (singleton pattern)
_embedder_instance: Optional[CaseEmbedder] = None


def get_embedder(
    model: str = "models/embedding-001",
    embedding_dim: int = 768,
) -> CaseEmbedder:
    """
    Get or create global embedder instance.
    
    Args:
        model: Embedding model name
        embedding_dim: Embedding dimension
    
    Returns:
        CaseEmbedder instance
    """
    global _embedder_instance
    
    if _embedder_instance is None:
        _embedder_instance = CaseEmbedder(
            model=model,
            embedding_dim=embedding_dim,
        )
    
    return _embedder_instance
