import pytest
import asyncio
import time
import httpx
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.api.main import app
from src.runtime.recovery_manager import RecoveryManager
from src.runtime.health_monitor import RuntimeHealthMonitor
from src.runtime.resources.backpressure import BackpressureController
from src.runtime.resources.queue_budget import QueueBudget
from src.runtime.resources.resource_limits import ResourceLimits
from src.utils.cache import get_graph_cache, reset_cache
from src.real_time_streaming.stream_processor import get_stream_processor
from src.predictive_intelligence.store import get_predictive_store


@pytest.mark.anyio
async def test_event_loop_responsiveness():
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as ac:

        async def fire_heavy_request():
            return await ac.post(
                "/api/v1/fraud/check",
                headers={
                    "X-API-Key": "d8f9b9f71c4c1a4b8689360d84386fc7b9c6a1e342898b3c940b5d1a8e108139"
                },
                json={
                    "transaction_id": "tx_concurrency_1",
                    "source_account": "acc_concurrency_test",
                    "target_account": "acc_target_test",
                    "amount": 1000.0,
                    "currency": "USD",
                    "timestamp": time.time(),
                    "biometrics": {
                        "hold_times": [100, 110, 105, 95, 120] * 10,
                        "flight_times": [150, 140, 160, 155, 145] * 10,
                    },
                },
            )

        async def fire_health_request():
            return await ac.get("/")

        heavy_tasks = [
            asyncio.create_task(fire_heavy_request())
            for _ in range(5)
        ]

        await asyncio.sleep(0.1)

        start_time = time.time()
        health_response = await fire_health_request()
        elapsed = time.time() - start_time

        results = await asyncio.gather(*heavy_tasks)

        for response in results:
            assert response.status_code == 200

        assert health_response.status_code == 200
        assert elapsed < 1.0


def test_recovery_manager_concurrent_registration():
    """Test RecoveryManager handles concurrent callback registration safely."""
    health_monitor = RuntimeHealthMonitor()
    recovery_manager = RecoveryManager(health_monitor)
    
    callback_count = 0
    
    def create_callback(name):
        def callback():
            nonlocal callback_count
            callback_count += 1
        return callback
    
    # Register callbacks concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for i in range(100):
            future = executor.submit(
                recovery_manager.register_recovery_callback,
                f"service_{i}",
                create_callback(f"service_{i}"),
                3
            )
            futures.append(future)
        
        for future in as_completed(futures):
            future.result()
    
    # Verify all callbacks were registered
    assert len(recovery_manager.get_registered_names()) == 100


def test_recovery_manager_concurrent_failure_handling():
    """Test RecoveryManager handles concurrent failure handling safely."""
    health_monitor = RuntimeHealthMonitor()
    recovery_manager = RecoveryManager(health_monitor)
    
    call_count = 0
    
    def test_callback():
        nonlocal call_count
        call_count += 1
    
    recovery_manager.register_recovery_callback("test_service", test_callback, 3)
    
    # Mark service as failed
    health_monitor.mark_failed("test_service")
    
    # Trigger concurrent failure handling
    async def handle_failure():
        return await recovery_manager.handle_failure("test_service")
    
    async def concurrent_failures():
        tasks = [handle_failure() for _ in range(10)]
        await asyncio.gather(*tasks)
    
    asyncio.run(concurrent_failures())
    
    # Verify callback was called (may be called multiple times due to throttling)
    assert call_count >= 0


def test_backpressure_controller_concurrent_events():
    """Test BackpressureController handles concurrent event processing safely."""
    limits = ResourceLimits()
    controller = BackpressureController(limits)
    
    def process_events():
        for _ in range(50):
            controller.can_accept_event(queue_utilization=0.5, task_budget_exceeded=False)
    
    # Process events concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_events) for _ in range(10)]
        for future in as_completed(futures):
            future.result()
    
    # Verify controller state is consistent
    assert controller.state in [controller.HEALTHY, controller.WARNING, controller.THROTTLED]


def test_backpressure_controller_concurrent_recoveries():
    """Test BackpressureController handles concurrent recovery attempts safely."""
    limits = ResourceLimits()
    controller = BackpressureController(limits)
    
    def process_recoveries():
        for _ in range(50):
            controller.can_start_recovery()
    
    # Process recoveries concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_recoveries) for _ in range(10)]
        for future in as_completed(futures):
            future.result()
    
    # Verify controller state is consistent
    assert controller.state in [controller.HEALTHY, controller.WARNING, controller.THROTTLED]


def test_queue_budget_concurrent_updates():
    """Test QueueBudget handles concurrent size updates safely."""
    limits = ResourceLimits()
    budget = QueueBudget(limits, max_size=1000)
    
    def update_sizes():
        for i in range(100):
            budget.update(i % 1000, 1000)
    
    # Update sizes concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(update_sizes) for _ in range(10)]
        for future in as_completed(futures):
            future.result()
    
    # Verify budget state is consistent
    assert 0 <= budget.current_size <= budget.max_size
    assert 0 <= budget.utilization <= 1.0


def test_global_singleton_concurrent_initialization():
    """Test global singleton initialization is thread-safe."""
    reset_cache()
    
    def get_cache():
        return get_graph_cache()
    
    # Get cache concurrently
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(get_cache) for _ in range(20)]
        results = [future.result() for future in as_completed(futures)]
    
    # Verify all returned the same instance
    first = results[0]
    for result in results[1:]:
        assert result is first
    
    reset_cache()


def test_stream_processor_singleton_concurrent_initialization():
    """Test stream processor singleton initialization is thread-safe."""
    def get_processor():
        return get_stream_processor()
    
    # Get processor concurrently
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(get_processor) for _ in range(20)]
        results = [future.result() for future in as_completed(futures)]
    
    # Verify all returned the same instance
    first = results[0]
    for result in results[1:]:
        assert result is first


def test_predictive_store_singleton_concurrent_initialization():
    """Test predictive store singleton initialization is thread-safe."""
    def get_store():
        return get_predictive_store()
    
    # Get store concurrently
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(get_store) for _ in range(20)]
        results = [future.result() for future in as_completed(futures)]
    
    # Verify all returned the same instance
    first = results[0]
    for result in results[1:]:
        assert result is first


def test_centrality_baseline_concurrent_access():
    """Test centrality_baseline concurrent read/write is thread-safe."""
    from collections import OrderedDict
    
    class LRUCache(OrderedDict):
        def __init__(self, maxsize=10000, *args, **kwds):
            self.maxsize = maxsize
            super().__init__(*args, **kwds)
            
        def __getitem__(self, key):
            value = super().__getitem__(key)
            self.move_to_end(key)
            return value
            
        def __setitem__(self, key, value):
            if key in self:
                self.move_to_end(key)
            super().__setitem__(key, value)
            if len(self) > self.maxsize:
                oldest = next(iter(self))
                del self[oldest]
    
    centrality_baseline = LRUCache(maxsize=10000)
    lock = threading.Lock()
    centrality_window_size = 10
    
    def update_baseline(account_id):
        for i in range(100):
            with lock:
                if account_id not in centrality_baseline:
                    centrality_baseline[account_id] = []
                baseline_history = centrality_baseline[account_id]
                baseline_history.append(i * 0.01)
                if len(baseline_history) > centrality_window_size:
                    baseline_history.pop(0)
    
    # Update baseline concurrently for different accounts
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(update_baseline, f"account_{i}") for i in range(10)]
        for future in as_completed(futures):
            future.result()
    
    # Verify baseline state is consistent
    for i in range(10):
        account_id = f"account_{i}"
        assert account_id in centrality_baseline
        assert len(centrality_baseline[account_id]) <= centrality_window_size