"""Unit tests for the multi-agent orchestration engine.

Covers ``src.agents.orchestration.engine``: ``AgentRegistry``, the four
execution strategies (sequential / parallel / hybrid / cascade), step
helpers, execution lifecycle, and the pre-built workflows.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from src.agents.base import AgentStatus, AgentTask, AgentType, BaseAgent
from src.agents.orchestration.engine import (
    AgentRegistry,
    OrchestrationEngine,
    OrchestrationStrategy,
    Workflow,
    WorkflowExecution,
    WorkflowStep,
    create_fraud_investigation_workflow,
    create_threat_hunting_workflow,
)


class StubAgent(BaseAgent):
    """Agent that echoes its input back as the task result."""

    async def initialize(self) -> bool:
        return True

    async def execute(self, task: AgentTask) -> dict:
        return dict(task.input_data)

    async def cleanup(self):
        pass


class ExplodingAgent(StubAgent):
    """Agent that always raises during execution."""

    async def execute(self, task: AgentTask) -> dict:
        raise RuntimeError("agent exploded")


class CapturingAgent(StubAgent):
    """Agent that records every input it receives and echoes it back."""

    def __init__(self, agent_id: str, agent_type: AgentType, config: dict):
        super().__init__(agent_id, agent_type, config)
        self.inputs: list[dict] = []

    async def execute(self, task: AgentTask) -> dict:
        received = dict(task.input_data)
        self.inputs.append(received)
        return {"seen": received}


@pytest.fixture
def engine() -> OrchestrationEngine:
    return OrchestrationEngine({"default_timeout": 10})


def _step(step_id: str, agent_type: AgentType, input_mapping=None, **kwargs) -> WorkflowStep:
    return WorkflowStep(
        step_id=step_id,
        agent_type=agent_type,
        input_mapping=input_mapping or {},
        **kwargs,
    )


def _sequential_workflow(steps=None, **kwargs) -> Workflow:
    return Workflow(
        workflow_id="wf-test",
        name="Test",
        description="desc",
        steps=steps or [
            _step("s1", AgentType.INVESTIGATION),
            _step("s2", AgentType.REPORTING, input_mapping={"in": "s1_output"}),
        ],
        strategy=OrchestrationStrategy.SEQUENTIAL,
        **kwargs,
    )


def _register(engine: OrchestrationEngine, agent_type: AgentType, agent: BaseAgent):
    engine.register_agent(agent_type, agent)


# ---------------------------------------------------------------------------
# AgentRegistry
# ---------------------------------------------------------------------------


class TestAgentRegistry:
    def test_register_and_get(self):
        registry = AgentRegistry()
        agent = StubAgent("a", AgentType.INVESTIGATION, {})

        registry.register(AgentType.INVESTIGATION, agent)

        assert registry.get(AgentType.INVESTIGATION) is agent
        assert registry.get(AgentType.FORENSICS) is None

    def test_factory_create(self):
        registry = AgentRegistry()
        registry.register_factory(AgentType.REPORTING, lambda config: StubAgent("a", AgentType.REPORTING, config))

        agent = registry.create(AgentType.REPORTING, {"k": "v"})
        assert isinstance(agent, StubAgent)
        assert agent.config == {"k": "v"}

    def test_factory_missing_raises(self):
        registry = AgentRegistry()
        with pytest.raises(ValueError):
            registry.create(AgentType.FORENSICS, {})

    def test_list_types(self):
        registry = AgentRegistry()
        registry.register(AgentType.INVESTIGATION, StubAgent("a", AgentType.INVESTIGATION, {}))
        registry.register(AgentType.FORENSICS, StubAgent("b", AgentType.FORENSICS, {}))

        assert set(registry.list_types()) == {AgentType.INVESTIGATION, AgentType.FORENSICS}


# ---------------------------------------------------------------------------
# Sequential execution
# ---------------------------------------------------------------------------


class TestSequential:
    def test_completed_workflow_with_results(self, engine):
        _register(engine, AgentType.INVESTIGATION, StubAgent("a", AgentType.INVESTIGATION, {}))
        _register(engine, AgentType.REPORTING, StubAgent("b", AgentType.REPORTING, {}))
        workflow = _sequential_workflow()

        execution = asyncio.run(engine.execute_workflow(workflow, {"seed": 1}))

        assert execution.status == AgentStatus.COMPLETED
        assert len(execution.step_results) == 2
        assert execution.current_step == 1
        assert execution.output is not None

    def test_conditions_skip_step(self, engine):
        _register(engine, AgentType.INVESTIGATION, StubAgent("a", AgentType.INVESTIGATION, {}))
        workflow = _sequential_workflow(steps=[
            _step("s1", AgentType.INVESTIGATION, conditions={"mode": "skip"}),
        ])

        execution = asyncio.run(engine.execute_workflow(workflow, {"mode": "run"}))

        assert execution.status == AgentStatus.COMPLETED
        assert execution.step_results == []

    def test_stop_on_failure_fails_workflow(self, engine):
        _register(engine, AgentType.INVESTIGATION, ExplodingAgent("a", AgentType.INVESTIGATION, {}))
        workflow = _sequential_workflow(steps=[
            _step("s1", AgentType.INVESTIGATION, on_failure="stop"),
        ])

        execution = asyncio.run(engine.execute_workflow(workflow, {}))

        assert execution.status == AgentStatus.FAILED
        assert len(execution.errors) == 1

    def test_missing_agent_fails_workflow(self, engine):
        workflow = _sequential_workflow(steps=[
            _step("s1", AgentType.FORENSICS),
        ])

        execution = asyncio.run(engine.execute_workflow(workflow, {}))

        assert execution.status == AgentStatus.FAILED


# ---------------------------------------------------------------------------
# Parallel execution
# ---------------------------------------------------------------------------


class TestParallel:
    def test_parallel_aggregates_results(self, engine):
        _register(engine, AgentType.INVESTIGATION, StubAgent("a", AgentType.INVESTIGATION, {}))
        _register(engine, AgentType.REPORTING, StubAgent("b", AgentType.REPORTING, {}))
        workflow = Workflow(
            workflow_id="wf-par",
            name="P",
            description="d",
            strategy=OrchestrationStrategy.PARALLEL,
            max_parallel=1,
            steps=[
                _step("s1", AgentType.INVESTIGATION),
                _step("s2", AgentType.REPORTING),
            ],
        )

        execution = asyncio.run(engine.execute_workflow(workflow, {"seed": 1}))

        assert execution.status == AgentStatus.COMPLETED
        assert len(execution.step_results) == 2
        assert isinstance(execution.output, dict)
        assert len(execution.output["results"]) == 2

    def test_parallel_stop_on_error_fails_workflow(self, engine):
        _register(engine, AgentType.INVESTIGATION, ExplodingAgent("a", AgentType.INVESTIGATION, {}))
        workflow = Workflow(
            workflow_id="wf-par",
            name="P",
            description="d",
            strategy=OrchestrationStrategy.PARALLEL,
            steps=[_step("s1", AgentType.INVESTIGATION, on_failure="stop")],
        )

        execution = asyncio.run(engine.execute_workflow(workflow, {}))

        assert execution.status == AgentStatus.FAILED
        assert len(execution.errors) == 1


# ---------------------------------------------------------------------------
# Hybrid execution
# ---------------------------------------------------------------------------


class TestHybrid:
    def test_hybrid_executes_groups(self, engine):
        _register(engine, AgentType.INVESTIGATION, StubAgent("a", AgentType.INVESTIGATION, {}))
        _register(engine, AgentType.REPORTING, StubAgent("b", AgentType.REPORTING, {}))
        workflow = Workflow(
            workflow_id="wf-hyb",
            name="H",
            description="d",
            strategy=OrchestrationStrategy.HYBRID,
            steps=[
                _step("s1", AgentType.INVESTIGATION, input_mapping={"x": "seed"}),
                _step("s2", AgentType.REPORTING, input_mapping={"y": "seed"}),
            ],
        )

        execution = asyncio.run(engine.execute_workflow(workflow, {"seed": 5}))

        assert execution.status == AgentStatus.COMPLETED
        # Both steps are dependent, forming one parallel group -> step_results
        # are recorded by the hybrid parallel branch.
        assert len(execution.step_results) == 2
        assert execution.output is not None


# ---------------------------------------------------------------------------
# Cascade execution
# ---------------------------------------------------------------------------


class TestCascade:
    def test_cascade_feeds_output_forward(self, engine):
        _register(engine, AgentType.INVESTIGATION, StubAgent("a", AgentType.INVESTIGATION, {}))
        _register(engine, AgentType.REPORTING, StubAgent("b", AgentType.REPORTING, {}))
        workflow = Workflow(
            workflow_id="wf-cas",
            name="C",
            description="d",
            strategy=OrchestrationStrategy.CASCADE,
            steps=[
                _step("s1", AgentType.INVESTIGATION),
                _step("s2", AgentType.REPORTING),
            ],
        )

        execution = asyncio.run(engine.execute_workflow(workflow, {"seed": 1}))

        assert execution.status == AgentStatus.COMPLETED
        assert len(execution.step_results) == 2
        # Output is the last step's result, which includes cascade_output.
        assert "cascade_output" in execution.output


# ---------------------------------------------------------------------------
# Step helpers
# ---------------------------------------------------------------------------


class TestStepHelpers:
    def test_evaluate_conditions(self, engine):
        assert engine._evaluate_conditions({"mode": "x"}, {"mode": "x", "k": 1}) is True
        assert engine._evaluate_conditions({"mode": "x"}, {"mode": "y"}) is False
        assert engine._evaluate_conditions({"missing": "x"}, {"mode": "x"}) is False

    def test_map_outputs_prefers_new_result(self, engine):
        current = {"seed": 1, "steps": []}
        result = {"s1_output": "v"}

        mapped = engine._map_outputs({"in": "s1_output"}, current, result, "s1")

        assert mapped["in"] == "v"
        assert mapped["s1_output"] == result

    def test_map_outputs_falls_back_to_current(self, engine):
        current = {"seed": 1}
        result = {}

        mapped = engine._map_outputs({"in": "seed"}, current, result, "s1")

        assert mapped["in"] == 1

    def test_map_outputs_guards_none_result(self, engine):
        current = {"seed": 1}

        mapped = engine._map_outputs({"in": "seed"}, current, None, "s1")

        assert mapped == {"seed": 1}

    def test_map_outputs_stores_per_step_key(self, engine):
        current = {"seed": 1}

        mapped = engine._map_outputs({}, current, {"evidence": "e1"}, "collect_evidence")

        assert mapped["collect_evidence_output"] == {"evidence": "e1"}

    def test_group_steps_by_dependencies(self, engine):
        independent = _step("s1", AgentType.INVESTIGATION)
        dependent = _step("s2", AgentType.REPORTING, input_mapping={"x": "y"})

        groups = engine._group_steps_by_dependencies([independent, dependent])

        assert groups[0] == [independent]
        assert groups[1] == [dependent]

    def test_execute_step_missing_agent_raises(self, engine):
        step = _step("s1", AgentType.FORENSICS)
        execution = WorkflowExecution(execution_id="e", workflow_id="wf", status=AgentStatus.RUNNING)

        with pytest.raises(ValueError):
            asyncio.run(engine._execute_step(step, {}, execution, None))


# ---------------------------------------------------------------------------
# Execution lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_execution_is_tracked(self, engine):
        _register(engine, AgentType.INVESTIGATION, StubAgent("a", AgentType.INVESTIGATION, {}))

        execution = asyncio.run(engine.execute_workflow(_sequential_workflow(), {}))

        assert engine.get_workflow_status(execution.execution_id) is execution
        assert engine.get_workflow_status("missing") is None

    def test_cancel_running_workflow(self, engine):
        execution = WorkflowExecution(execution_id="e1", workflow_id="wf", status=AgentStatus.RUNNING)
        engine.active_workflows["e1"] = execution

        assert engine.cancel_workflow("e1") is True
        assert execution.status == AgentStatus.FAILED
        assert len(execution.errors) == 1

    def test_cancel_unknown_or_completed(self, engine):
        execution = WorkflowExecution(execution_id="e1", workflow_id="wf", status=AgentStatus.COMPLETED)
        engine.active_workflows["e1"] = execution

        assert engine.cancel_workflow("missing") is False
        assert engine.cancel_workflow("e1") is False


# ---------------------------------------------------------------------------
# Pre-built workflows
# ---------------------------------------------------------------------------


class TestPrebuiltWorkflows:
    def test_fraud_investigation_workflow(self):
        workflow = create_fraud_investigation_workflow()

        assert workflow.workflow_id == "fraud_investigation_v1"
        assert workflow.strategy == OrchestrationStrategy.SEQUENTIAL
        assert len(workflow.steps) == 5
        assert workflow.steps[0].step_id == "collect_evidence"

    def test_threat_hunting_workflow(self):
        workflow = create_threat_hunting_workflow()

        assert workflow.workflow_id == "threat_hunting_v1"
        assert workflow.strategy == OrchestrationStrategy.PARALLEL
        assert workflow.max_parallel == 3
        assert len(workflow.steps) >= 4

    def test_fraud_workflow_forwards_upstream_outputs(self, engine):
        agents = {}
        for agent_type in [
            AgentType.INVESTIGATION,
            AgentType.THREAT_INTELLIGENCE,
            AgentType.COMPLIANCE,
            AgentType.FORENSICS,
            AgentType.REPORTING,
        ]:
            agent = CapturingAgent(agent_type.value, agent_type, {})
            _register(engine, agent_type, agent)
            agents[agent_type] = agent

        workflow = create_fraud_investigation_workflow()
        execution = asyncio.run(
            engine.execute_workflow(workflow, {"case_id": "C-1", "evidence_raw": "raw"})
        )

        assert execution.status == AgentStatus.COMPLETED

        evidence_output = {"seen": {"case_id": "C-1", "evidence_raw": "raw"}}

        # Downstream steps receive the upstream steps' outputs.
        threat_input = agents[AgentType.THREAT_INTELLIGENCE].inputs[0]
        assert threat_input["collect_evidence_output"] == evidence_output

        compliance_input = agents[AgentType.COMPLIANCE].inputs[0]
        assert compliance_input["evidence"] == evidence_output

        forensic_input = agents[AgentType.FORENSICS].inputs[0]
        assert forensic_input["evidence"] == evidence_output
        assert forensic_input["context"] == forensic_input["threat_analysis_output"]

        report_input = agents[AgentType.REPORTING].inputs[0]
        assert report_input["collect_evidence_output"] == evidence_output
        assert report_input["threat_analysis_output"] is not None

        # Every step's output is chained into the workflow output, and the
        # report step's mapping is applied to produce the final output.
        for step_key in (
            "collect_evidence_output",
            "threat_analysis_output",
            "compliance_check_output",
            "forensic_analysis_output",
        ):
            assert step_key in execution.output
        assert execution.output["investigation"] == evidence_output
        assert execution.output["threats"] == execution.output["threat_analysis_output"]
        assert execution.output["compliance"] == execution.output["compliance_check_output"]
        assert execution.output["forensics"] == execution.output["forensic_analysis_output"]
