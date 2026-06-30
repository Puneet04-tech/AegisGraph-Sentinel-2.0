"""
Concurrency regression tests for singleton initialization patterns.

Tests verify that:
1. Only one singleton instance is created under concurrent access
2. All threads receive the same instance
3. Initialization remains correct under concurrency
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Type, Any

import pytest

# Import all singleton modules
from src.observability.audit_logger import get_audit_logger, AuditLogger, _audit_logger, _audit_logger_lock
from src.config.settings import get_settings, RuntimeSettings, _settings_cache, _settings_cache_lock, reset_settings_cache
from src.utils.cache import get_graph_cache, GraphOperationCache, _cache_instance, _cache_instance_lock, reset_cache
from src.features.honeypot_escrow import get_honeypot_manager, HoneypotEscrowManager, _honeypot_manager, _honeypot_manager_lock
from src.features.blockchain_evidence import get_blockchain_manager, BlockchainEvidenceManager, _blockchain_manager, _blockchain_manager_lock
from src.features.predictive_mule_identification import _get_mule_scorer, PredictiveMuleScorer, _mule_scorer_instance, _mule_scorer_instance_lock
from src.api.validators import get_rate_limiter, RateLimiter, _rate_limiter, _rate_limiter_lock


def reset_all_singletons():
    """Reset all singleton instances for testing."""
    global _audit_logger, _settings_cache, _cache_instance
    global _honeypot_manager, _blockchain_manager, _mule_scorer_instance, _rate_limiter
    
    with _audit_logger_lock:
        globals()['_audit_logger'] = None
    
    with _settings_cache_lock:
        globals()['_settings_cache'] = None
    
    with _cache_instance_lock:
        globals()['_cache_instance'] = None
    
    with _honeypot_manager_lock:
        globals()['_honeypot_manager'] = None
    
    with _blockchain_manager_lock:
        globals()['_blockchain_manager'] = None
    
    with _mule_scorer_instance_lock:
        globals()['_mule_scorer_instance'] = None
    
    with _rate_limiter_lock:
        globals()['_rate_limiter'] = None


class TestAuditLoggerThreadSafety:
    """Test thread-safe initialization of AuditLogger singleton."""
    
    def teardown_method(self):
        """Reset singleton after each test."""
        global _audit_logger
        with _audit_logger_lock:
            globals()['_audit_logger'] = None
    
    def test_concurrent_initialization_creates_single_instance(self):
        """Verify only one AuditLogger instance is created under concurrent access."""
        instances: List[AuditLogger] = []
        
        def get_instance():
            instance = get_audit_logger()
            instances.append(instance)
            time.sleep(0.001)  # Simulate some work
            return instance
        
        # Create 50 threads that all try to get the singleton simultaneously
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_instance) for _ in range(50)]
            for future in as_completed(futures):
                future.result()
        
        # Verify all instances are the same object
        first_instance = instances[0]
        for instance in instances:
            assert instance is first_instance, "All threads should receive the same instance"
        
        # Verify only one instance was created
        unique_instances = set(id(inst) for inst in instances)
        assert len(unique_instances) == 1, f"Expected 1 unique instance, got {len(unique_instances)}"
    
    def test_singleton_returns_same_instance_on_repeated_calls(self):
        """Verify singleton returns the same instance on repeated calls."""
        instance1 = get_audit_logger()
        instance2 = get_audit_logger()
        instance3 = get_audit_logger()
        
        assert instance1 is instance2 is instance3


class TestSettingsCacheThreadSafety:
    """Test thread-safe initialization of RuntimeSettings singleton."""
    
    def teardown_method(self):
        """Reset singleton after each test."""
        reset_settings_cache()
    
    def test_concurrent_initialization_creates_single_instance(self):
        """Verify only one RuntimeSettings instance is created under concurrent access."""
        instances: List[RuntimeSettings] = []
        
        def get_instance():
            instance = get_settings()
            instances.append(instance)
            time.sleep(0.001)
            return instance
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_instance) for _ in range(50)]
            for future in as_completed(futures):
                future.result()
        
        first_instance = instances[0]
        for instance in instances:
            assert instance is first_instance, "All threads should receive the same instance"
        
        unique_instances = set(id(inst) for inst in instances)
        assert len(unique_instances) == 1, f"Expected 1 unique instance, got {len(unique_instances)}"
    
    def test_singleton_returns_same_instance_on_repeated_calls(self):
        """Verify singleton returns the same instance on repeated calls."""
        instance1 = get_settings()
        instance2 = get_settings()
        instance3 = get_settings()
        
        assert instance1 is instance2 is instance3


class TestGraphCacheThreadSafety:
    """Test thread-safe initialization of GraphOperationCache singleton."""
    
    def teardown_method(self):
        """Reset singleton after each test."""
        reset_cache()
    
    def test_concurrent_initialization_creates_single_instance(self):
        """Verify only one GraphOperationCache instance is created under concurrent access."""
        instances: List[GraphOperationCache] = []
        
        def get_instance():
            instance = get_graph_cache()
            instances.append(instance)
            time.sleep(0.001)
            return instance
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_instance) for _ in range(50)]
            for future in as_completed(futures):
                future.result()
        
        first_instance = instances[0]
        for instance in instances:
            assert instance is first_instance, "All threads should receive the same instance"
        
        unique_instances = set(id(inst) for inst in instances)
        assert len(unique_instances) == 1, f"Expected 1 unique instance, got {len(unique_instances)}"
    
    def test_singleton_returns_same_instance_on_repeated_calls(self):
        """Verify singleton returns the same instance on repeated calls."""
        instance1 = get_graph_cache()
        instance2 = get_graph_cache()
        instance3 = get_graph_cache()
        
        assert instance1 is instance2 is instance3


class TestHoneypotManagerThreadSafety:
    """Test thread-safe initialization of HoneypotEscrowManager singleton."""
    
    def teardown_method(self):
        """Reset singleton after each test."""
        global _honeypot_manager
        with _honeypot_manager_lock:
            globals()['_honeypot_manager'] = None
    
    def test_concurrent_initialization_creates_single_instance(self):
        """Verify only one HoneypotEscrowManager instance is created under concurrent access."""
        instances: List[HoneypotEscrowManager] = []
        
        def get_instance():
            instance = get_honeypot_manager()
            instances.append(instance)
            time.sleep(0.001)
            return instance
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_instance) for _ in range(50)]
            for future in as_completed(futures):
                future.result()
        
        first_instance = instances[0]
        for instance in instances:
            assert instance is first_instance, "All threads should receive the same instance"
        
        unique_instances = set(id(inst) for inst in instances)
        assert len(unique_instances) == 1, f"Expected 1 unique instance, got {len(unique_instances)}"
    
    def test_singleton_returns_same_instance_on_repeated_calls(self):
        """Verify singleton returns the same instance on repeated calls."""
        instance1 = get_honeypot_manager()
        instance2 = get_honeypot_manager()
        instance3 = get_honeypot_manager()
        
        assert instance1 is instance2 is instance3


class TestBlockchainManagerThreadSafety:
    """Test thread-safe initialization of BlockchainEvidenceManager singleton."""
    
    def teardown_method(self):
        """Reset singleton after each test."""
        global _blockchain_manager
        with _blockchain_manager_lock:
            globals()['_blockchain_manager'] = None
    
    def test_concurrent_initialization_creates_single_instance(self):
        """Verify only one BlockchainEvidenceManager instance is created under concurrent access."""
        instances: List[BlockchainEvidenceManager] = []
        
        def get_instance():
            instance = get_blockchain_manager()
            instances.append(instance)
            time.sleep(0.001)
            return instance
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_instance) for _ in range(50)]
            for future in as_completed(futures):
                future.result()
        
        first_instance = instances[0]
        for instance in instances:
            assert instance is first_instance, "All threads should receive the same instance"
        
        unique_instances = set(id(inst) for inst in instances)
        assert len(unique_instances) == 1, f"Expected 1 unique instance, got {len(unique_instances)}"
    
    def test_singleton_returns_same_instance_on_repeated_calls(self):
        """Verify singleton returns the same instance on repeated calls."""
        instance1 = get_blockchain_manager()
        instance2 = get_blockchain_manager()
        instance3 = get_blockchain_manager()
        
        assert instance1 is instance2 is instance3


class TestMuleScorerThreadSafety:
    """Test thread-safe initialization of PredictiveMuleScorer singleton."""
    
    def teardown_method(self):
        """Reset singleton after each test."""
        global _mule_scorer_instance
        with _mule_scorer_instance_lock:
            globals()['_mule_scorer_instance'] = None
    
    def test_concurrent_initialization_creates_single_instance(self):
        """Verify only one PredictiveMuleScorer instance is created under concurrent access."""
        instances: List[PredictiveMuleScorer] = []
        
        def get_instance():
            instance = _get_mule_scorer()
            instances.append(instance)
            time.sleep(0.001)
            return instance
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_instance) for _ in range(50)]
            for future in as_completed(futures):
                future.result()
        
        first_instance = instances[0]
        for instance in instances:
            assert instance is first_instance, "All threads should receive the same instance"
        
        unique_instances = set(id(inst) for inst in instances)
        assert len(unique_instances) == 1, f"Expected 1 unique instance, got {len(unique_instances)}"
    
    def test_singleton_returns_same_instance_on_repeated_calls(self):
        """Verify singleton returns the same instance on repeated calls."""
        instance1 = _get_mule_scorer()
        instance2 = _get_mule_scorer()
        instance3 = _get_mule_scorer()
        
        assert instance1 is instance2 is instance3


class TestRateLimiterThreadSafety:
    """Test thread-safe initialization of RateLimiter singleton."""
    
    def teardown_method(self):
        """Reset singleton after each test."""
        global _rate_limiter
        with _rate_limiter_lock:
            globals()['_rate_limiter'] = None
    
    def test_concurrent_initialization_creates_single_instance(self):
        """Verify only one RateLimiter instance is created under concurrent access."""
        instances: List[RateLimiter] = []
        
        def get_instance():
            instance = get_rate_limiter()
            instances.append(instance)
            time.sleep(0.001)
            return instance
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_instance) for _ in range(50)]
            for future in as_completed(futures):
                future.result()
        
        first_instance = instances[0]
        for instance in instances:
            assert instance is first_instance, "All threads should receive the same instance"
        
        unique_instances = set(id(inst) for inst in instances)
        assert len(unique_instances) == 1, f"Expected 1 unique instance, got {len(unique_instances)}"
    
    def test_singleton_returns_same_instance_on_repeated_calls(self):
        """Verify singleton returns the same instance on repeated calls."""
        instance1 = get_rate_limiter()
        instance2 = get_rate_limiter()
        instance3 = get_rate_limiter()
        
        assert instance1 is instance2 is instance3


class TestAllSingletonsConcurrently:
    """Test all singletons can be initialized concurrently without conflicts."""
    
    def teardown_method(self):
        """Reset all singletons after each test."""
        reset_all_singletons()
    
    def test_all_singletons_thread_safety(self):
        """Verify all singletons maintain thread-safety when initialized concurrently."""
        results = {
            'audit_logger': [],
            'settings': [],
            'cache': [],
            'honeypot': [],
            'blockchain': [],
            'mule_scorer': [],
            'rate_limiter': [],
        }
        
        def initialize_all():
            results['audit_logger'].append(get_audit_logger())
            results['settings'].append(get_settings())
            results['cache'].append(get_graph_cache())
            results['honeypot'].append(get_honeypot_manager())
            results['blockchain'].append(get_blockchain_manager())
            results['mule_scorer'].append(_get_mule_scorer())
            results['rate_limiter'].append(get_rate_limiter())
        
        # Run 20 threads initializing all singletons
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(initialize_all) for _ in range(20)]
            for future in as_completed(futures):
                future.result()
        
        # Verify each singleton has only one unique instance
        for singleton_name, instances in results.items():
            unique_ids = set(id(inst) for inst in instances)
            assert len(unique_ids) == 1, f"{singleton_name}: Expected 1 unique instance, got {len(unique_ids)}"
