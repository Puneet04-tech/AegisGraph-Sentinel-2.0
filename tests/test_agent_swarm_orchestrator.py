"""Unit tests for the agent swarm orchestrator.

Covers ``src.agent_swarm.orchestrator.AgentOrchestrator``: default agent
registration, task queueing/prioritization, assignment, completion/failure
handling, agent messaging, and swarm intelligence metrics.
"""

from __future__ import annotations

import pytest

from src.agent_swarm.models import AgentStatus, AgentType, TaskPriority, TaskStatus
from src.agent_swarm.orchestrator import AgentOrchestrator


@pytest.fixture
def orchestrator() -> AgentOrchestrator:
    return AgentOrchestrator()


# ---------------------------------------------------------------------------
# Default agents
# ---------------------------------------------------------------------------


class TestDefaultAgents:
    def test_eight_default_agents_registered(self, orchestrator):
        assert len(orchestrator.agents) == 8

    def test_default_agents_cover_all_expected_types(self, orchestrator):
        types = {a.agent_type for a in orchestrator.agents.values()}
        assert AgentType.FRAUD_AGENT in types
        assert AgentType.THREAT_HUNTING_AGENT in types
        assert AgentType.AML_AGENT in types
        assert AgentType.COMPLIANCE_AGENT in types
        assert AgentType.INVESTIGATION_AGENT in types
        assert AgentType.FORENSICS_AGENT in types
        assert AgentType.RISK_AGENT in types
        assert AgentType.RESPONSE_AGENT in types

    def test_default_agents_start_idle(self, orchestrator):
        assert all(a.status == AgentStatus.IDLE for a in orchestrator.agents.values())


# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------


class TestAgentRegistration:
    def test_register_agent_returns_id_and_stores(self, orchestrator):
        agent_id = orchestrator.register_agent(
            AgentType.FRAUD_AGENT, "Custom Fraud Agent", ["fraud_detection"]
        )

        agent = orchestrator.get_agent(agent_id)
        assert agent is not None
        assert agent.name == "Custom Fraud Agent"
        assert agent.capabilities == ["fraud_detection"]
        assert agent.status == AgentStatus.IDLE

    def test_register_agent_defaults_capabilities(self, orchestrator):
        agent_id = orchestrator.register_agent(AgentType.RISK_AGENT, "Risk Agent")
        assert orchestrator.get_agent(agent_id).capabilities == []

    def test_get_agent_unknown_id_returns_none(self, orchestrator):
        assert orchestrator.get_agent("missing") is None

    def test_get_agents_by_type_filters(self, orchestrator):
        fraud_agents = orchestrator.get_agents_by_type(AgentType.FRAUD_AGENT)

        assert len(fraud_agents) == 1
        assert all(a.agent_type == AgentType.FRAUD_AGENT for a in fraud_agents)

    def test_get_available_agents_returns_only_idle(self, orchestrator):
        agent_id = orchestrator.get_agents_by_type(AgentType.FRAUD_AGENT)[0].agent_id
        task_id = orchestrator.create_task("analysis", "Analyze batch")
        orchestrator.assign_task(task_id, agent_id)

        available = orchestrator.get_available_agents()
        assert all(a.agent_id != agent_id for a in available)
        assert all(a.status == AgentStatus.IDLE for a in available)


# ---------------------------------------------------------------------------
# Task creation and priority queue
# ---------------------------------------------------------------------------


class TestTaskQueue:
    def test_create_task_adds_to_queue(self, orchestrator):
        task_id = orchestrator.create_task(
            "analysis", "Analyze anomalies", priority=TaskPriority.HIGH
        )

        assert task_id in orchestrator.task_queue
        assert orchestrator.tasks[task_id].status == TaskStatus.PENDING
        assert orchestrator.tasks[task_id].input_data == {}

    def test_queue_sorts_by_priority(self, orchestrator):
        low = orchestrator.create_task("t", "low", priority=TaskPriority.LOW)
        critical = orchestrator.create_task("t", "critical", priority=TaskPriority.CRITICAL)
        medium = orchestrator.create_task("t", "medium", priority=TaskPriority.MEDIUM)

        # CRITICAL must be pulled first, then MEDIUM, then LOW.
        assert orchestrator.task_queue[0] == critical
        assert orchestrator.task_queue[1] == medium
        assert orchestrator.task_queue[2] == low

    def test_queue_reorders_when_new_higher_priority_arrives(self, orchestrator):
        medium = orchestrator.create_task("t", "medium", priority=TaskPriority.MEDIUM)
        critical = orchestrator.create_task("t", "critical", priority=TaskPriority.CRITICAL)

        assert orchestrator.task_queue == [critical, medium]


# ---------------------------------------------------------------------------
# Task assignment
# ---------------------------------------------------------------------------


class TestTaskAssignment:
    def test_assign_task_unknown_task_fails(self, orchestrator):
        agent_id = next(iter(orchestrator.agents))
        assert orchestrator.assign_task("missing", agent_id) is False

    def test_assign_task_unknown_agent_fails(self, orchestrator):
        task_id = orchestrator.create_task("t", "work")
        assert orchestrator.assign_task(task_id, "missing") is False

    def test_assign_task_busy_agent_fails(self, orchestrator):
        agent_id = next(iter(orchestrator.agents))
        first = orchestrator.create_task("t1", "one")
        second = orchestrator.create_task("t2", "two")

        assert orchestrator.assign_task(first, agent_id) is True
        assert orchestrator.assign_task(second, agent_id) is False

    def test_assign_task_success_transitions_state(self, orchestrator):
        agent_id = next(iter(orchestrator.agents))
        task_id = orchestrator.create_task("t", "work")

        assert orchestrator.assign_task(task_id, agent_id) is True

        task = orchestrator.tasks[task_id]
        agent = orchestrator.agents[agent_id]
        assert task.status == TaskStatus.ASSIGNED
        assert task.assigned_agent == agent_id
        assert agent.status == AgentStatus.BUSY
        assert agent.current_task == task_id


# ---------------------------------------------------------------------------
# Task completion and failure
# ---------------------------------------------------------------------------


class TestTaskCompletion:
    def test_complete_task_unknown_fails(self, orchestrator):
        assert orchestrator.complete_task("missing") is False

    def test_complete_task_sets_output_and_frees_agent(self, orchestrator):
        agent_id = next(iter(orchestrator.agents))
        task_id = orchestrator.create_task("t", "work")
        orchestrator.assign_task(task_id, agent_id)

        assert orchestrator.complete_task(task_id, {"result": "ok"}) is True

        task = orchestrator.tasks[task_id]
        agent = orchestrator.agents[agent_id]
        assert task.status == TaskStatus.COMPLETED
        assert task.output_data == {"result": "ok"}
        assert task.completed_at is not None
        assert agent.status == AgentStatus.IDLE
        assert agent.current_task is None
        assert agent.tasks_completed == 1

    def test_complete_task_unassigned_task_still_succeeds(self, orchestrator):
        task_id = orchestrator.create_task("t", "work")
        assert orchestrator.complete_task(task_id) is True
        assert orchestrator.tasks[task_id].status == TaskStatus.COMPLETED

    def test_fail_task_sets_error_and_frees_agent(self, orchestrator):
        agent_id = next(iter(orchestrator.agents))
        task_id = orchestrator.create_task("t", "work")
        orchestrator.assign_task(task_id, agent_id)

        assert orchestrator.fail_task(task_id, "timeout") is True

        task = orchestrator.tasks[task_id]
        agent = orchestrator.agents[agent_id]
        assert task.status == TaskStatus.FAILED
        assert task.error_message == "timeout"
        assert task.completed_at is not None
        assert agent.status == AgentStatus.IDLE
        assert agent.current_task is None

    def test_fail_task_unknown_fails(self, orchestrator):
        assert orchestrator.fail_task("missing", "error") is False


# ---------------------------------------------------------------------------
# Agent messaging
# ---------------------------------------------------------------------------


class TestMessaging:
    def test_send_message_stores_message(self, orchestrator):
        agent_a = next(iter(orchestrator.agents))
        agent_b = orchestrator.register_agent(AgentType.RISK_AGENT, "Risk B")

        message_id = orchestrator.send_message(
            agent_a, agent_b, "query", {"key": "value"}
        )

        assert message_id in orchestrator.messages
        assert orchestrator.messages[message_id].from_agent == agent_a
        assert orchestrator.messages[message_id].to_agent == agent_b
        assert orchestrator.messages[message_id].message_type == "query"

    def test_get_agent_messages_filters_by_to_and_from(self, orchestrator):
        agent_a = next(iter(orchestrator.agents))
        agent_b = orchestrator.register_agent(AgentType.RISK_AGENT, "Risk B")
        orchestrator.send_message(agent_a, agent_b, "q1", {})
        orchestrator.send_message(agent_b, agent_a, "q2", {})

        received = orchestrator.get_agent_messages(agent_a)
        assert len(received) == 2
        assert all(m.to_agent == agent_a or m.from_agent == agent_a for m in received)


# ---------------------------------------------------------------------------
# Swarm intelligence metrics
# ---------------------------------------------------------------------------


class TestSwarmIntelligence:
    def test_get_swarm_intelligence_counts_agents(self, orchestrator):
        intelligence = orchestrator.get_swarm_intelligence()

        assert intelligence.total_agents == 8
        assert intelligence.active_agents == 8
        assert intelligence.tasks_completed == 0

    def test_tasks_completed_accumulate(self, orchestrator):
        agent_id = next(iter(orchestrator.agents))
        for _ in range(2):
            task_id = orchestrator.create_task("t", "work")
            orchestrator.assign_task(task_id, agent_id)
            orchestrator.complete_task(task_id)

        intelligence = orchestrator.get_swarm_intelligence()
        assert intelligence.tasks_completed == 2

    def test_collaboration_score_default_with_no_tasks(self, orchestrator):
        assert orchestrator._calculate_collaboration_score() == 0.5

    def test_collaboration_score_rises_with_messages(self, orchestrator):
        agent_a = next(iter(orchestrator.agents))
        task_id = orchestrator.create_task("t", "work")
        orchestrator.assign_task(task_id, agent_a)
        orchestrator.complete_task(task_id)

        assert orchestrator._calculate_collaboration_score() == 0.0

        agent_b = orchestrator.register_agent(AgentType.RISK_AGENT, "Risk B")
        orchestrator.send_message(agent_a, agent_b, "q", {})
        orchestrator.send_message(agent_b, agent_a, "r", {})

        assert orchestrator._calculate_collaboration_score() == pytest.approx(1.0)

    def test_get_orchestrator_stats_counts(self, orchestrator):
        agent_id = next(iter(orchestrator.agents))
        task_id = orchestrator.create_task("t", "work")
        orchestrator.assign_task(task_id, agent_id)
        orchestrator.complete_task(task_id)

        stats = orchestrator.get_orchestrator_stats()
        assert stats["total_agents"] == 8
        assert stats["total_tasks"] == 1
        assert stats["completed_tasks"] == 1
        assert stats["failed_tasks"] == 0
        assert stats["idle_agents"] == 8
        assert stats["active_agents"] == 0
