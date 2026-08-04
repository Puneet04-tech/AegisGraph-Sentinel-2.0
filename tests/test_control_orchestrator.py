"""Tests for ControlOrchestrator"""
import pytest

from src.control_plane import orchestrator as orchestrator_module
from src.control_plane.orchestrator import ControlOrchestrator
from src.control_plane.models import (
    SecurityControl,
    ControlExecution,
    Workflow,
    ControlStatus,
    ModuleType,
    PolicyType,
)


def test_init_registers_default_controls():
    orch = ControlOrchestrator()
    assert len(orch.controls) == 4
    assert set(orch.controls.keys()) == {"ctrl-001", "ctrl-002", "ctrl-003", "ctrl-004"}


def test_default_control_attributes():
    orch = ControlOrchestrator()
    fraud = orch.get_control("ctrl-001")
    assert fraud is not None
    assert fraud.name == "Fraud Detection Control"
    assert fraud.module_type == ModuleType.FRAUD
    assert fraud.policy_type == PolicyType.SECURITY
    assert fraud.priority == 1
    assert fraud.enabled is True

    cti = orch.get_control("ctrl-002")
    assert cti is not None
    assert cti.module_type == ModuleType.CTI

    governance = orch.get_control("ctrl-003")
    assert governance is not None
    assert governance.module_type == ModuleType.GOVERNANCE
    assert governance.policy_type == PolicyType.ACCESS

    risk = orch.get_control("ctrl-004")
    assert risk is not None
    assert risk.module_type == ModuleType.RISK
    assert risk.policy_type == PolicyType.OPERATIONAL


def test_add_control_returns_id_and_registers():
    orch = ControlOrchestrator()
    control = SecurityControl(
        control_id="ctrl-custom",
        name="Custom",
        description="desc",
        module_type=ModuleType.COMPLIANCE,
        policy_type=PolicyType.DATA,
    )
    result = orch.add_control(control)
    assert result == "ctrl-custom"
    assert orch.get_control("ctrl-custom") is control


def test_add_control_duplicate_overwrites():
    orch = ControlOrchestrator()
    original = SecurityControl(
        control_id="ctrl-dup",
        name="Original",
        description="desc",
        module_type=ModuleType.SOC,
        policy_type=PolicyType.SECURITY,
        priority=1,
    )
    replacement = SecurityControl(
        control_id="ctrl-dup",
        name="Replacement",
        description="desc2",
        module_type=ModuleType.RISK,
        policy_type=PolicyType.OPERATIONAL,
        priority=5,
    )
    orch.add_control(original)
    orch.add_control(replacement)
    assert len(orch.controls) == 5
    assert orch.get_control("ctrl-dup") is replacement


def test_add_control_default_enabled_and_priority():
    orch = ControlOrchestrator()
    control = SecurityControl(
        control_id="ctrl-pri",
        name="Pri",
        description="desc",
        module_type=ModuleType.INVESTIGATION,
        policy_type=PolicyType.ACCESS,
    )
    orch.add_control(control)
    stored = orch.get_control("ctrl-pri")
    assert stored.enabled is True
    assert stored.priority == 1
    assert stored.created_at is not None


def test_get_control_missing_returns_none():
    orch = ControlOrchestrator()
    assert orch.get_control("does-not-exist") is None


def test_get_controls_by_module():
    orch = ControlOrchestrator()
    controls = orch.get_controls_by_module(ModuleType.FRAUD)
    assert [c.control_id for c in controls] == ["ctrl-001"]
    assert all(c.module_type == ModuleType.FRAUD for c in controls)


def test_get_controls_by_module_empty():
    orch = ControlOrchestrator()
    assert orch.get_controls_by_module(ModuleType.DEFENSE_GRID) == []


def test_get_controls_by_module_multiple():
    orch = ControlOrchestrator()
    for i in range(3):
        orch.add_control(
            SecurityControl(
                control_id=f"ctrl-soc-{i}",
                name=f"SOC {i}",
                description="desc",
                module_type=ModuleType.SOC,
                policy_type=PolicyType.SECURITY,
            )
        )
    controls = orch.get_controls_by_module(ModuleType.SOC)
    assert len(controls) == 3


def test_execute_control_completed():
    orch = ControlOrchestrator()
    execution = orch.execute_control("ctrl-001")
    assert execution.status == ControlStatus.COMPLETED
    assert execution.module_type == ModuleType.FRAUD
    assert execution.result == {"success": True, "control": "Fraud Detection Control"}
    assert execution.error is None
    assert execution.started_at is not None
    assert execution.completed_at is not None
    assert execution.completed_at.tzinfo is not None
    assert orch.executions[execution.execution_id] is execution


def test_execute_control_unknown_control_fails():
    orch = ControlOrchestrator()
    execution = orch.execute_control("missing-ctrl")
    assert execution.status == ControlStatus.FAILED
    assert execution.error == "Control not found"
    assert execution.module_type == ModuleType.FRAUD
    assert execution.result is None
    assert execution.completed_at is None
    assert orch.executions[execution.execution_id] is execution


def test_execute_control_unique_execution_ids():
    orch = ControlOrchestrator()
    first = orch.execute_control("ctrl-002")
    second = orch.execute_control("ctrl-002")
    assert first.execution_id != second.execution_id
    assert len(orch.executions) == 2


def test_execution_status_transitions(monkeypatch):
    constructed = {}

    class SpyControlExecution(ControlExecution):
        def __init__(self, *args, **kwargs):
            constructed["status"] = kwargs.get("status")
            constructed["control_id"] = kwargs.get("control_id")
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(orchestrator_module, "ControlExecution", SpyControlExecution)
    orch = ControlOrchestrator()
    execution = orch.execute_control("ctrl-003")
    assert constructed["control_id"] == "ctrl-003"
    assert constructed["status"] == ControlStatus.RUNNING
    assert execution.status == ControlStatus.COMPLETED


def test_execution_failure_status_transition(monkeypatch):
    constructed = {}

    class SpyControlExecution(ControlExecution):
        def __init__(self, *args, **kwargs):
            constructed["status"] = kwargs.get("status")
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(orchestrator_module, "ControlExecution", SpyControlExecution)
    orch = ControlOrchestrator()
    execution = orch.execute_control("nope")
    assert constructed["status"] == ControlStatus.FAILED
    assert execution.status == ControlStatus.FAILED


def test_create_workflow_steps_ordered():
    orch = ControlOrchestrator()
    workflow = orch.create_workflow(
        name="Ordered",
        description="desc",
        control_ids=["ctrl-003", "ctrl-001", "ctrl-002"],
        modules=["GOVERNANCE", "FRAUD", "CTI"],
    )
    assert workflow.name == "Ordered"
    assert workflow.description == "desc"
    assert [s["step"] for s in workflow.steps] == [1, 2, 3]
    assert [s["control_id"] for s in workflow.steps] == ["ctrl-003", "ctrl-001", "ctrl-002"]
    assert [s["control_name"] for s in workflow.steps] == [
        "Governance Policy Control",
        "Fraud Detection Control",
        "CTI Feed Control",
    ]
    assert all(s["timeout"] == 60 for s in workflow.steps)


def test_create_workflow_unknown_control_name():
    orch = ControlOrchestrator()
    workflow = orch.create_workflow(
        name="Unknown",
        description="desc",
        control_ids=["ctrl-001", "ghost"],
        modules=["FRAUD"],
    )
    assert workflow.steps[0]["control_name"] == "Fraud Detection Control"
    assert workflow.steps[1]["control_name"] == "Unknown"


def test_create_workflow_empty_steps():
    orch = ControlOrchestrator()
    workflow = orch.create_workflow(
        name="Empty",
        description="desc",
        control_ids=[],
        modules=[],
    )
    assert workflow.steps == []
    assert workflow.modules_involved == []
    assert workflow.enabled is True


def test_create_workflow_modules_converted_to_enums():
    orch = ControlOrchestrator()
    workflow = orch.create_workflow(
        name="Mods",
        description="desc",
        control_ids=["ctrl-001"],
        modules=["FRAUD", "RISK", "COMPLIANCE"],
    )
    assert workflow.modules_involved == [ModuleType.FRAUD, ModuleType.RISK, ModuleType.COMPLIANCE]


def test_create_workflow_invalid_module_raises():
    orch = ControlOrchestrator()
    with pytest.raises(ValueError):
        orch.create_workflow(
            name="Bad",
            description="desc",
            control_ids=["ctrl-001"],
            modules=["NOT_A_MODULE"],
        )


def test_workflows_stored_and_retrievable():
    orch = ControlOrchestrator()
    workflow = orch.create_workflow(
        name="Stored",
        description="desc",
        control_ids=["ctrl-001"],
        modules=["FRAUD"],
    )
    assert orch.get_workflow(workflow.workflow_id) is workflow
    assert orch.workflows[workflow.workflow_id] is workflow


def test_get_workflow_missing_returns_none():
    orch = ControlOrchestrator()
    assert orch.get_workflow("missing") is None


def test_get_all_workflows():
    orch = ControlOrchestrator()
    assert orch.get_all_workflows() == []
    wf_a = orch.create_workflow("A", "desc", ["ctrl-001"], ["FRAUD"])
    wf_b = orch.create_workflow("B", "desc", ["ctrl-002"], ["CTI"])
    workflows = orch.get_all_workflows()
    assert set(w.workflow_id for w in workflows) == {wf_a.workflow_id, wf_b.workflow_id}


def test_workflow_ids_unique():
    orch = ControlOrchestrator()
    wf_a = orch.create_workflow("A", "desc", ["ctrl-001"], ["FRAUD"])
    wf_b = orch.create_workflow("B", "desc", ["ctrl-001"], ["FRAUD"])
    assert wf_a.workflow_id != wf_b.workflow_id
    assert len(orch.workflows) == 2


def test_get_execution_stats_initial():
    orch = ControlOrchestrator()
    stats = orch.get_execution_stats()
    assert stats["total_controls"] == 4
    assert stats["total_executions"] == 0
    assert stats["total_workflows"] == 0
    assert stats["execution_by_status"] == {}


def test_get_execution_stats_counts_statuses():
    orch = ControlOrchestrator()
    orch.execute_control("ctrl-001")
    orch.execute_control("ctrl-002")
    orch.execute_control("missing")
    orch.create_workflow("W", "desc", ["ctrl-001"], ["FRAUD"])
    stats = orch.get_execution_stats()
    assert stats["total_controls"] == 4
    assert stats["total_executions"] == 3
    assert stats["total_workflows"] == 1
    assert stats["execution_by_status"] == {
        ControlStatus.COMPLETED.value: 2,
        ControlStatus.FAILED.value: 1,
    }


def test_get_execution_stats_counts_controls_with_added():
    orch = ControlOrchestrator()
    orch.add_control(
        SecurityControl(
            control_id="ctrl-x",
            name="X",
            description="desc",
            module_type=ModuleType.COMPLIANCE,
            policy_type=PolicyType.DATA,
        )
    )
    stats = orch.get_execution_stats()
    assert stats["total_controls"] == 5


def test_execution_to_dict_roundtrip():
    orch = ControlOrchestrator()
    execution = orch.execute_control("ctrl-004")
    data = execution.to_dict()
    assert data["execution_id"] == execution.execution_id
    assert data["status"] == ControlStatus.COMPLETED.value
    assert data["module_type"] == ModuleType.RISK.value
    assert data["result"] == {"success": True, "control": "Risk Assessment Control"}
    assert data["completed_at"] is not None


def test_workflow_to_dict_roundtrip():
    orch = ControlOrchestrator()
    workflow = orch.create_workflow("W", "desc", ["ctrl-001"], ["FRAUD"])
    data = workflow.to_dict()
    assert data["workflow_id"] == workflow.workflow_id
    assert data["name"] == "W"
    assert data["modules_involved"] == ["FRAUD"]
    assert data["enabled"] is True
    assert data["steps"][0]["step"] == 1
