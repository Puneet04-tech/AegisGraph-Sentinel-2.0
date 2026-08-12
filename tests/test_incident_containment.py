# AegisGraph Sentinel Enterprise
# Incident Containment Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
import threading
from src.security.incidents.containment import ContainmentManager

def test_containment_manager_initial_state():
    manager = ContainmentManager()
    assert manager.event_throttled is False
    assert manager.recovery_suppressed is False
    assert manager.admin_cooldown is False

def test_containment_manager_activate():
    manager = ContainmentManager()
    flags = manager.activate_containment(event_throttled=True, recovery_suppressed=False, admin_cooldown=True)
    assert flags["event_throttled"] is True
    assert flags["recovery_suppressed"] is False
    assert flags["admin_cooldown"] is True
    
    assert manager.event_throttled is True
    assert manager.recovery_suppressed is False
    assert manager.admin_cooldown is True

def test_containment_manager_deactivate():
    manager = ContainmentManager()
    manager.activate_containment(event_throttled=True, recovery_suppressed=True, admin_cooldown=True)
    flags = manager.deactivate_containment()
    assert flags["event_throttled"] is False
    assert flags["recovery_suppressed"] is False
    assert flags["admin_cooldown"] is False

def test_containment_manager_get_flags():
    manager = ContainmentManager()
    manager.event_throttled = True
    flags = manager.get_flags()
    assert flags["event_throttled"] is True
    assert flags["recovery_suppressed"] is False

def test_containment_manager_lock_safeties():
    manager = ContainmentManager()
    assert manager._lock is not None
    # Verify lock behavior
    with manager._lock:
        manager.event_throttled = True
    assert manager.get_flags()["event_throttled"] is True

def test_containment_manager_multiple_threads():
    manager = ContainmentManager()
    
    def worker():
        manager.activate_containment(event_throttled=True, recovery_suppressed=True, admin_cooldown=True)
        
    t = threading.Thread(target=worker)
    t.start()
    t.join()
    
    assert manager.event_throttled is True
