from src.soar.store import SOARStore
from src.soar.service import SOARService

_store = None
_service = None

def get_store() -> SOARStore:
    global _store
    if _store is None:
        _store = SOARStore()
    return _store

def get_soar_service() -> SOARService:
    global _service
    if _service is None:
        store_instance = get_store()
        _service = SOARService(store=store_instance)
    return _service
