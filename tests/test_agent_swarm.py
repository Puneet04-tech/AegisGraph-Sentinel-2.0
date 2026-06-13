"""
Tests for Agent Swarm Module
"""
import pytest
from datetime import datetime, timezone

from src.agent_swarm import (
    AgentOrchestrator,
    get_orchestrator,
    SwarmIntelligenceLayer,
    get_swarm_intelligence,
    AgentType,
    AgentStatus,
    TaskPriority,
    TaskStatus,
    Agent,
    Task,
    FraudDetectionAgent,
    ThreatHuntingAgent,
    AMLMonitoringAgent,
)


class TestAgentOrchestrator:
    """Tests for AgentOrchestrator."""
    
    def setup_method(self):
        self.orchestrator = AgentOrchestrator()
    
    def test_initialization(self):
        """Test orchestrator initialization."""
        assert len(self.orchestrator.agents) > 0
        assert len(self.orchestrator.tasks) == 0
    
    def test_register_agent(self):
        """Test agent registration."""
        agent_id = self.orchestrator.register_agent(
            agent_type=AgentType.INTELLIGENCE_AGENT,
            name="Test Agent",
            capabilities=["test"],
        )
        assert agent_id is not None
        assert self.orchestrator.get_agent(agent_id) is not None
    
    def test_get_agents_by_type(self):
        """Test getting agents by type."""
        agents = self.orchestrator.get_agents_by_type(AgentType.FRAUD_AGENT)
        assert len(agents) >= 1
        assert all(a.agent_type == AgentType.FRAUD_AGENT for a in agents)
    
    def test_get_available_agents(self):
        """Test getting available agents."""
        agents = self.orchestrator.get_available_agents()
        assert len(agents) >= 1
    
    def test_create_task(self):
        """Test task creation."""
        task_id = self.orchestrator.create_task(
            task_type="fraud_analysis",
            description="Analyze transaction",
            priority=TaskPriority.HIGH,
        )
        assert task_id is not None
        assert task_id in self.orchestrator.tasks
    
    def test_assign_task(self):
        """Test task assignment."""
        task_id = self.orchestrator.create_task(
            task_type="test_task",
            description="Test task",
        )
        
        available = self.orchestrator.get_available_agents()
        if available:
            success = self.orchestrator.assign_task(task_id, available[0].agent_id)
            assert success is True
            assert self.orchestrator.tasks[task_id].status == TaskStatus.ASSIGNED
    
    def test_complete_task(self):
        """Test task completion."""
        task_id = self.orchestrator.create_task(
            task_type="test_task",
            description="Test task",
        )
        
        success = self.orchestrator.complete_task(task_id, {"result": "success"})
        assert success is True
        assert self.orchestrator.tasks[task_id].status == TaskStatus.COMPLETED
    
    def test_fail_task(self):
        """Test task failure."""
        task_id = self.orchestrator.create_task(
            task_type="test_task",
            description="Test task",
        )
        
        success = self.orchestrator.fail_task(task_id, "Test error")
        assert success is True
        assert self.orchestrator.tasks[task_id].status == TaskStatus.FAILED
    
    def test_send_message(self):
        """Test agent messaging."""
        agents = self.orchestrator.get_available_agents()
        if len(agents) >= 2:
            msg_id = self.orchestrator.send_message(
                from_agent=agents[0].agent_id,
                to_agent=agents[1].agent_id,
                message_type="ALERT",
                content={"alert": "test"},
            )
            assert msg_id is not None
    
    def test_get_orchestrator_stats(self):
        """Test getting statistics."""
        stats = self.orchestrator.get_orchestrator_stats()
        assert "total_agents" in stats
        assert "total_tasks" in stats
        assert "total_messages" in stats


class TestSwarmIntelligenceLayer:
    """Tests for SwarmIntelligenceLayer."""
    
    def setup_method(self):
        self.swarm = SwarmIntelligenceLayer(AgentOrchestrator())
    
    def test_detect_emergent_behavior(self):
        """Test emergent behavior detection."""
        behaviors = self.swarm.detect_emergent_behavior()
        assert isinstance(behaviors, list)
    
    def test_orchestrate_task(self):
        """Test task orchestration."""
        task_id = self.swarm.orchestrate_task(
            task_type="fraud_analysis",
            task_data={"transaction_id": "test-123"},
        )
        assert task_id is not None
    
    def test_get_intelligence_report(self):
        """Test intelligence report generation."""
        report = self.swarm.get_intelligence_report()
        assert "swarm_id" in report
        assert "performance_metrics" in report
        assert "recommendations" in report


class TestSpecializedAgents:
    """Tests for specialized agents."""
    
    def test_fraud_detection_agent(self):
        """Test fraud detection agent."""
        agent = FraudDetectionAgent("test-agent")
        
        result = agent.analyze_transaction({
            "transaction_id": "tx-123",
            "amount": 15000,
            "velocity": 6,
            "new_recipient": True,
        })
        
        assert "risk_score" in result
        assert "risk_factors" in result
        assert result["recommendation"] == "BLOCK"
    
    def test_threat_hunting_agent(self):
        """Test threat hunting agent."""
        agent = ThreatHuntingAgent("test-agent")
        
        result = agent.hunt_threats({
            "indicators": ["malware.exe", "suspicious-domain.com"],
        })
        
        assert "threats_found" in result
        assert "recommendation" in result
    
    def test_aml_monitoring_agent(self):
        """Test AML monitoring agent."""
        agent = AMLMonitoringAgent("test-agent")
        
        result = agent.monitor_transactions({
            "amount": 15000,
            "international": True,
            "shell_company": True,
        })
        
        assert "red_flags" in result
        assert len(result["red_flags"]) >= 2


class TestModels:
    """Tests for model classes."""
    
    def test_agent_to_dict(self):
        """Test Agent serialization."""
        agent = Agent(
            agent_id="test-1",
            agent_type=AgentType.FRAUD_AGENT,
            name="Test Agent",
            status=AgentStatus.IDLE,
        )
        
        data = agent.to_dict()
        assert data["agent_id"] == "test-1"
        assert data["agent_type"] == "FRAUD_AGENT"
    
    def test_task_to_dict(self):
        """Test Task serialization."""
        task = Task(
            task_id="task-1",
            task_type="test",
            description="Test task",
            priority=TaskPriority.HIGH,
        )
        
        data = task.to_dict()
        assert data["task_id"] == "task-1"
        assert data["priority"] == "HIGH"
    
    def test_agent_type_values(self):
        """Test AgentType enum values."""
        assert AgentType.FRAUD_AGENT.value == "FRAUD_AGENT"
        assert AgentType.THREAT_HUNTING_AGENT.value == "THREAT_HUNTING_AGENT"
        assert len(AgentType) > 0
    
    def test_task_status_values(self):
        """Test TaskStatus enum values."""
        assert TaskStatus.PENDING.value == "PENDING"
        assert TaskStatus.COMPLETED.value == "COMPLETED"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])