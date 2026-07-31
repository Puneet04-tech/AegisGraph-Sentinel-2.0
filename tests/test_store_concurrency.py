import threading
import pytest
from src.adaptive_auth.store import AdaptiveAuthStore


def test_concurrent_session_creation_and_lookup():
    store = AdaptiveAuthStore()
    num_threads = 50
    sessions_per_thread = 20
    created_session_ids = []
    lock = threading.Lock()

    def worker(user_idx):
        for i in range(sessions_per_thread):
            user_id = f"user_{user_idx}_{i}"
            session = store.create_session(user_id=user_id)
            with lock:
                created_session_ids.append(session.session_id)

    threads = [
        threading.Thread(target=worker, args=(t,))
        for t in range(num_threads)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(created_session_ids) == num_threads * sessions_per_thread

    # Verify O(1) thread-safe lookup for created sessions
    for session_id in created_session_ids:
        session = store.get_session(session_id)
        assert session is not None
        assert session.session_id == session_id


def test_concurrent_batch_score_updates():
    store = AdaptiveAuthStore()
    num_threads = 20

    def worker(thread_id):
        updates = {
            f"node_{thread_id}_{i}": {"score": 0.5 + (i * 0.01)}
            for i in range(50)
        }
        store.batch_update_scores(updates)

    threads = [
        threading.Thread(target=worker, args=(t,))
        for t in range(num_threads)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()


def test_defensive_copy_isolation():
    store = AdaptiveAuthStore()
    session = store.create_session(user_id="user_test_copy")

    retrieved = store.get_session(session.session_id)
    assert retrieved is not None

    # Mutating returned copy must not alter store internal state
    retrieved.ip_address = "999.999.999.999"

    fresh_fetch = store.get_session(session.session_id)
    assert fresh_fetch.ip_address != "999.999.999.999"
