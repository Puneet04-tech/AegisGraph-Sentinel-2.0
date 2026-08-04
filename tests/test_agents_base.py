"""Unit tests for the AI agent base framework.

Covers ``src.agents.base``: ``BaseAgent`` lifecycle and metrics,
``AgentTask`` / ``AgentMessage`` / ``AgentCapability`` dataclasses,
``LLMClient`` text generation, the ``Tool`` hierarchy, and
``AgentToolRegistry``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from src.agents.base import (
    APITool,
    AgentCapability,
    AgentMessage,
    AgentStatus,
    AgentTask,
    AgentToolRegistry,
    AgentType,
    BaseAgent,
    DatabaseTool,
    GraphTool,
    LLMClient,
    SearchTool,
    TaskPriority,
    tool_registry,
)


class EchoAgent(BaseAgent):
    """Concrete test agent."""

    async def initialize(self) -> bool:
        return True

    async def execute(self, task: AgentTask) -> dict:
        return {"echo": task.input_data.get("value")}

    async def cleanup(self):
        pass


class FailingAgent(BaseAgent):
    """Agent whose execute always raises."""

    async def initialize(self) -> bool:
        return True

    async def execute(self, task: AgentTask) -> dict:
        raise RuntimeError("boom")

    async def cleanup(self):
        pass


def _task(value: str = "x") -> AgentTask:
    return AgentTask(
        id="task-1",
        agent_type=AgentType.INVESTIGATION,
        priority=TaskPriority.HIGH,
        input_data={"value": value},
        created_at=datetime.now(timezone.utc),
    )


def _message() -> AgentMessage:
    return AgentMessage(
        id="msg-1",
        sender="agent-a",
        recipient=None,
        content={"data": 1},
        timestamp=datetime.now(timezone.utc),
        message_type="broadcast",
    )


# ---------------------------------------------------------------------------
# Enums and dataclasses
# ---------------------------------------------------------------------------


class TestEnums:
    def test_agent_status_values(self):
        assert AgentStatus.IDLE.value == "idle"
        assert AgentStatus.COMPLETED.value == "completed"
        assert AgentStatus.FAILED.value == "failed"

    def test_agent_type_values(self):
        assert AgentType.INVESTIGATION.value == "investigation"
        assert AgentType.THREAT_INTELLIGENCE.value == "threat_intelligence"

    def test_task_priority_values(self):
        assert TaskPriority.CRITICAL.value == "critical"

    def test_agent_task_defaults(self):
        task = _task()
        assert task.status == AgentStatus.IDLE
        assert task.dependencies == []
        assert task.result is None
        assert task.error is None

    def test_agent_message_defaults(self):
        message = _message()
        assert message.correlation_id is None
        assert message.reply_to is None


# ---------------------------------------------------------------------------
# BaseAgent
# ---------------------------------------------------------------------------


def _run_completion(agent: BaseAgent, task: AgentTask) -> None:
    """Run the agent loop as a background task, submit *task*, then stop."""

    async def _drive():
        runner = asyncio.create_task(agent.run())
        await agent.submit_task(task)
        await asyncio.sleep(0.2)
        agent.stop()
        await asyncio.wait_for(runner, timeout=5)

    asyncio.run(_drive())


class TestBaseAgent:
    def test_initial_state(self):
        agent = EchoAgent("agent-1", AgentType.INVESTIGATION, {"k": "v"})

        assert agent.status == AgentStatus.IDLE
        assert agent.tasks_processed == 0
        assert agent.total_execution_time == 0.0
        assert agent.errors == 0
        assert agent.message_queue.qsize() == 0

    def test_register_capability(self):
        agent = EchoAgent("agent-1", AgentType.INVESTIGATION, {})
        agent.register_capability("analyze", "desc", {}, {}, execution_time_estimate=3.0)

        capability = agent.capabilities[0]
        assert isinstance(capability, AgentCapability)
        assert capability.name == "analyze"
        assert capability.execution_time_estimate == 3.0

    def test_run_completes_submitted_task(self):
        agent = EchoAgent("agent-1", AgentType.INVESTIGATION, {})
        task = _task(value="hello")

        _run_completion(agent, task)

        assert task.status == AgentStatus.COMPLETED
        assert task.result == {"echo": "hello"}
        assert task.completed_at is not None
        assert agent.tasks_processed == 1

    def test_process_task_failure_marks_failed(self):
        agent = FailingAgent("agent-1", AgentType.INVESTIGATION, {})
        task = _task()

        asyncio.run(agent.process_task(task))

        assert task.status == AgentStatus.FAILED
        assert task.error == "boom"
        assert agent.errors == 1

    def test_stop_halts_run_loop(self):
        agent = EchoAgent("agent-1", AgentType.INVESTIGATION, {})

        async def _drive():
            runner = asyncio.create_task(agent.run())
            await asyncio.sleep(0.2)
            agent.stop()
            await asyncio.wait_for(runner, timeout=5)

        asyncio.run(_drive())

        assert agent._running is False

    def test_get_metrics(self):
        agent = EchoAgent("agent-1", AgentType.INVESTIGATION, {})
        task = _task()

        asyncio.run(agent.process_task(task))

        metrics = agent.get_metrics()
        assert metrics["agent_id"] == "agent-1"
        assert metrics["agent_type"] == "investigation"
        assert metrics["tasks_processed"] == 1
        assert metrics["average_execution_time"] >= 0
        assert metrics["error_rate"] == 0.0

    def test_get_metrics_empty_agent(self):
        agent = EchoAgent("agent-1", AgentType.INVESTIGATION, {})

        metrics = agent.get_metrics()
        assert metrics["average_execution_time"] == 0
        assert metrics["queue_size"] == 0


# ---------------------------------------------------------------------------
# LLMClient
# ---------------------------------------------------------------------------


class TestLLMClient:
    def test_config_defaults(self):
        client = LLMClient({})
        assert client.model == "gpt-4"
        assert client.temperature == 0.7
        assert client.max_tokens == 2048
        assert client.api_key is None

    def test_config_overrides(self):
        client = LLMClient({"model": "local", "temperature": 0.1, "max_tokens": 100})
        assert client.model == "local"
        assert client.temperature == 0.1
        assert client.max_tokens == 100

    def test_generate_with_evidence_section(self):
        client = LLMClient({})
        prompt = "Evidence collected: [\"email-ioc\"]\nRisk indicators: []"

        result = asyncio.run(client.generate(prompt))

        assert "Analysis of evidence:" in result
        assert "email-ioc" in result
        assert "Risk indicators identified" not in result

    def test_generate_with_risk_indicators(self):
        client = LLMClient({})
        prompt = "Risk indicators: [\"VELOCITY_SPIKE\"]"

        result = asyncio.run(client.generate(prompt))

        assert "Risk indicators identified: [\"VELOCITY_SPIKE\"]" in result

    def test_generate_without_sections_uses_fallback(self):
        client = LLMClient({})
        result = asyncio.run(client.generate("plain prompt"))

        assert "Investigation analysis complete. Model: gpt-4" == result

    def test_generate_streaming_calls_callback(self):
        client = LLMClient({})
        chunks = []

        async def callback(chunk):
            chunks.append(chunk)

        result = asyncio.run(client.generate_streaming("plain prompt", callback=callback))

        assert len(chunks) > 0
        assert " ".join(chunks) == result


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


class TestTools:
    def test_search_tool(self):
        result = asyncio.run(SearchTool().execute("fraud"))

        assert result["total"] == 2
        assert result["query"] == "fraud"
        assert result["results"][0]["title"] == "Fraud Pattern Analysis"

    def test_database_tool(self):
        result = asyncio.run(DatabaseTool("mongodb://x").execute("SELECT 1"))

        assert result == {"rows": [], "columns": [], "count": 0}

    def test_api_tool(self):
        result = asyncio.run(APITool("https://api.example.com").execute("/v1/status"))

        assert result["status"] == 200

    def test_graph_tool(self):
        result = asyncio.run(GraphTool("bolt://localhost", "neo4j", "pwd").execute("MATCH (n)"))

        assert result == {"nodes": [], "edges": [], "count": 0}


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


class TestToolRegistry:
    def test_register_and_get(self):
        registry = AgentToolRegistry()
        tool = SearchTool()

        registry.register(tool)

        assert registry.get("search") is tool
        assert registry.get("missing") is None

    def test_list_tools(self):
        registry = AgentToolRegistry()
        registry.register(SearchTool())
        registry.register(DatabaseTool("conn"))

        assert set(registry.list_tools()) == {"search", "database"}

    def test_module_registry_has_defaults(self):
        assert "search" in tool_registry.list_tools()
        assert "graph" in tool_registry.list_tools()
