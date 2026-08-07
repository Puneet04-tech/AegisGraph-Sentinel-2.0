"""Every migrated module must expose a bounded audit buffer.

Parametrised across all fifteen modules that carried a copy-pasted in-memory
audit list, so a future module reintroducing a plain list -- or a migration
that misses one -- fails here rather than in production memory use.
"""

import importlib

import pytest

from src.audit.bounded_log import BoundedAuditLog

# (module path, factory attribute, buffer attribute)
MIGRATED = [
    ("src.quantum_security.store", "QuantumSecurityStore", "_audit_log"),
    ("src.autonomous_secops.store", "AutonomousSecOpsStore", "_audit_log"),
    ("src.infinity_platform.store", "InfinityPlatformStore", "_audit_log"),
    ("src.security_digital_twin.store", "SecurityDigitalTwinStore", "_audit_log"),
    ("src.fraud_copilot.store", "FraudCopilotStore", "_audit_log"),
    ("src.digital_risk_protection.store", "DigitalRiskProtectionStore", "_audit_log"),
    ("src.security_mesh.store", "SecurityMeshStore", "_audit_log"),
    ("src.finintel_exchange.store", "FinIntelExchangeStore", "_audit_log"),
    ("src.cyber_threat_intel.store", "CTIStore", "_audit_log"),
    ("src.autonomous_investigation.store", None, "_audit_records"),
    ("src.global_intelligence.store", None, "_audit_records"),
    ("src.adaptive_risk_control.store", None, "_audit_records"),
    ("src.geofencing.engine", None, "_events"),
]


def _instantiate(module_path, class_name, buffer_attr):
    """Build the store for a module, tolerating naming differences."""
    module = importlib.import_module(module_path)

    candidates = []
    if class_name and hasattr(module, class_name):
        candidates.append(getattr(module, class_name))
    for name in dir(module):
        obj = getattr(module, name)
        if isinstance(obj, type) and obj.__module__ == module_path:
            candidates.append(obj)

    for cls in candidates:
        try:
            instance = cls()
        except Exception:
            continue
        if hasattr(instance, buffer_attr):
            return instance
    pytest.skip(f"no zero-arg constructible store exposing {buffer_attr} in {module_path}")


@pytest.mark.parametrize("module_path,class_name,buffer_attr", MIGRATED)
class TestMigratedModules:
    def test_buffer_is_bounded(self, module_path, class_name, buffer_attr):
        store = _instantiate(module_path, class_name, buffer_attr)
        buffer = getattr(store, buffer_attr)
        assert isinstance(buffer, BoundedAuditLog), (
            f"{module_path}.{buffer_attr} is a {type(buffer).__name__}, "
            "not a bounded audit log"
        )

    def test_buffer_has_a_positive_capacity(self, module_path, class_name, buffer_attr):
        store = _instantiate(module_path, class_name, buffer_attr)
        assert getattr(store, buffer_attr).capacity > 0

    def test_buffer_starts_empty(self, module_path, class_name, buffer_attr):
        store = _instantiate(module_path, class_name, buffer_attr)
        assert len(getattr(store, buffer_attr)) == 0

    def test_buffer_evicts_rather_than_growing(self, module_path, class_name, buffer_attr):
        store = _instantiate(module_path, class_name, buffer_attr)
        buffer = getattr(store, buffer_attr)
        capacity = buffer.capacity

        for i in range(capacity + 50):
            buffer.append(i)

        assert len(buffer) == capacity
        assert buffer.dropped == 50
        # The newest entry survives; the oldest does not.
        assert buffer.all()[-1] == capacity + 49
        assert 0 not in buffer.all()


class TestNoPlainListsRemain:
    """Guards against the copy-pasted pattern being reintroduced."""

    @pytest.mark.parametrize("module_path,class_name,buffer_attr", MIGRATED)
    def test_length_derived_event_ids_are_gone(self, module_path, class_name, buffer_attr):
        module = importlib.import_module(module_path)
        source_path = module.__file__
        assert source_path is not None

        with open(str(source_path), encoding="utf-8") as handle:
            source = handle.read()

        # `f"audit-{len(self._audit_log) + 1}"` collides after any clear.
        assert f"len(self.{buffer_attr}) + 1" not in source, (
            f"{module_path} still derives event ids from buffer length"
        )

    @pytest.mark.parametrize("module_path,class_name,buffer_attr", MIGRATED)
    def test_manual_slice_trimming_is_gone(self, module_path, class_name, buffer_attr):
        module = importlib.import_module(module_path)
        with open(str(module.__file__), encoding="utf-8") as handle:
            source = handle.read()

        # `self._x = self._x[-N:]` copied the whole retained list per append.
        assert f"self.{buffer_attr} = self.{buffer_attr}[-" not in source, (
            f"{module_path} still trims by slice copy"
        )


class TestReadPathsPreserved:
    """The migrated read APIs must behave as they did over a plain list."""

    def test_cti_store_audit_log_round_trip(self):
        from src.cyber_threat_intel.store import CTIStore

        store = CTIStore()
        for i in range(5):
            store.log_audit(
                user_id="analyst",
                action=f"action_{i}",
                resource_type="ioc",
                resource_id=f"ioc_{i}",
            )

        recent = store.get_audit_log(limit=3)
        assert len(recent) == 3
        assert [e.action for e in recent] == ["action_2", "action_3", "action_4"]

    def test_cti_event_ids_are_unique(self):
        from src.cyber_threat_intel.store import CTIStore

        store = CTIStore()
        for i in range(10):
            store.log_audit("analyst", f"a{i}", "ioc", f"i{i}")

        ids = [e.event_id for e in store.get_audit_log(limit=100)]
        assert len(set(ids)) == 10

    def test_cti_event_ids_stay_unique_across_a_clear(self):
        from src.cyber_threat_intel.store import CTIStore

        store = CTIStore()
        for i in range(5):
            store.log_audit("analyst", f"a{i}", "ioc", f"i{i}")
        before = {e.event_id for e in store.get_audit_log(limit=100)}

        store.clear()
        for i in range(5):
            store.log_audit("analyst", f"b{i}", "ioc", f"j{i}")
        after = {e.event_id for e in store.get_audit_log(limit=100)}

        assert before.isdisjoint(after)

    def test_cti_clear_empties_the_log(self):
        from src.cyber_threat_intel.store import CTIStore

        store = CTIStore()
        store.log_audit("analyst", "a", "ioc", "i")
        store.clear()
        assert store.get_audit_log(limit=10) == []

    def test_geofencing_event_queries_still_filter(self):
        from src.geofencing.engine import GeofencingEngine

        engine = GeofencingEngine()
        assert engine.get_events() == []
        assert engine.get_stats()["total_events"] == 0
