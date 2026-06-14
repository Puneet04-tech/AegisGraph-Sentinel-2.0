"""
Agent Swarm Orchestrator
Orchestrates distributed AI security agents.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4
import asyncio

from .models import (
    Agent,
    AgentStatus,
    AgentType,
    Task,
    TaskPriority,
    TaskStatus,
    AgentMessage,
    SwarmIntelligence,
)


class AgentOrchestrator:
    """Orchestrates the agent swarm."""
    
    def __init__(self):
        self.agents: Dict[str, Agent] = {}
        self.tasks: Dict[str, Task] = {}
        self.messages: Dict[str, AgentMessage] = {}
        self.task_queue: List[str] = []
        self._initialize_default_agents()
    
    def _initialize_default_agents(self):
        """Initialize default security agents."""
        default_agents = [
            (AgentType.FRAUD_AGENT, "Fraud Detection Agent", ["fraud_detection", "pattern_analysis"]),
            (AgentType.THREAT_HUNTING_AGENT, "Threat Hunting Agent", ["threat_detection", "ioc_analysis"]),
            (AgentType.AML_AGENT, "AML Monitoring Agent", ["transaction_monitoring", "sar_generation"]),
            (AgentType.COMPLIANCE_AGENT, "Compliance Agent", ["policy_check", "regulation_tracking"]),
            (AgentType.INVESTIGATION_AGENT, "Investigation Agent", ["evidence_gathering", "case_management"]),
            (AgentType.FORENSICS_AGENT, "Forensics Agent", ["digital_forensics", "data_recovery"]),
            (AgentType.RISK_AGENT, "Risk Assessment Agent", ["risk_scoring", "impact_analysis"]),
            (AgentType.RESPONSE_AGENT, "Response Agent", ["incident_response", "containment"]),
        ]
        
        for agent_type, name, capabilities in default_agents:
            self.register_agent(agent_type, name, capabilities)
    
    def register_agent(
        self,
        agent_type: AgentType,
        name: str,
        capabilities: Optional[List[str]] = None,
    ) -> str:
        """Register a new agent."""
        agent_id = str(uuid4())
        agent = Agent(
            agent_id=agent_id,
            agent_type=agent_type,
            name=name,
            capabilities=capabilities or [],
        )
        self.agents[agent_id] = agent
        return agent_id
    
    def get_agent(self, agent_id: str) -> Optional[Agent]:
        """Get agent by ID."""
        return self.agents.get(agent_id)
    
    def get_agents_by_type(self, agent_type: AgentType) -> List[Agent]:
        """Get all agents of a specific type."""
        return [a for a in self.agents.values() if a.agent_type == agent_type]
    
    def get_available_agents(self) -> List[Agent]:
        """Get all available (idle) agents."""
        return [a for a in self.agents.values() if a.status == AgentStatus.IDLE]
    
    def create_task(
        self,
        task_type: str,
        description: str,
        priority: TaskPriority = TaskPriority.MEDIUM,
        input_data: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a new task."""
        task_id = str(uuid4())
        task = Task(
            task_id=task_id,
            task_type=task_type,
            description=description,
            priority=priority,
            input_data=input_data or {},
        )
        self.tasks[task_id] = task
        self.task_queue.append(task_id)
        self._sort_task_queue()
        return task_id
    
    def _sort_task_queue(self):
        """Sort task queue by priority."""
        priority_order = {
            TaskPriority.CRITICAL: 0,
            TaskPriority.HIGH: 1,
            TaskPriority.MEDIUM: 2,
            TaskPriority.LOW: 3,
        }
        
        self.task_queue.sort(
            key=lambda tid: priority_order.get(self.tasks[tid].priority, 99)
        )
    
    def assign_task(self, task_id: str, agent_id: str) -> bool:
        """Assign a task to an agent."""
        task = self.tasks.get(task_id)
        agent = self.agents.get(agent_id)
        
        if not task or not agent:
            return False
        
        if agent.status != AgentStatus.IDLE:
            return False
        
        task.status = TaskStatus.ASSIGNED
        task.assigned_agent = agent_id
        agent.status = AgentStatus.BUSY
        agent.current_task = task_id
        
        return True
    
    def complete_task(
        self,
        task_id: str,
        output_data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Mark a task as completed."""
        task = self.tasks.get(task_id)
        if not task:
            return False
        
        task.status = TaskStatus.COMPLETED
        task.output_data = output_data
        task.completed_at = datetime.now(timezone.utc)
        
        if task.assigned_agent:
            agent = self.agents.get(task.assigned_agent)
            if agent:
                agent.status = AgentStatus.IDLE
                agent.current_task = None
                agent.tasks_completed += 1
        
        return True
    
    def fail_task(self, task_id: str, error: str) -> bool:
        """Mark a task as failed."""
        task = self.tasks.get(task_id)
        if not task:
            return False
        
        task.status = TaskStatus.FAILED
        task.error_message = error
        task.completed_at = datetime.now(timezone.utc)
        
        if task.assigned_agent:
            agent = self.agents.get(task.assigned_agent)
            if agent:
                agent.status = AgentStatus.IDLE
                agent.current_task = None
        
        return True
    
    def send_message(
        self,
        from_agent: str,
        to_agent: str,
        message_type: str,
        content: Dict[str, Any],
        correlation_id: Optional[str] = None,
    ) -> str:
        """Send a message between agents."""
        message_id = str(uuid4())
        message = AgentMessage(
            message_id=message_id,
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=message_type,
            content=content,
            correlation_id=correlation_id,
        )
        self.messages[message_id] = message
        return message_id
    
    def get_agent_messages(self, agent_id: str) -> List[AgentMessage]:
        """Get messages for an agent."""
        return [
            m for m in self.messages.values()
            if m.to_agent == agent_id or m.from_agent == agent_id
        ]
    
    def get_swarm_intelligence(self) -> SwarmIntelligence:
        """Get swarm intelligence metrics."""
        active = sum(1 for a in self.agents.values() if a.status != AgentStatus.OFFLINE)
        avg_success = (
            sum(a.success_rate for a in self.agents.values()) / max(1, len(self.agents))
        )
        
        return SwarmIntelligence(
            swarm_id=str(uuid4()),
            total_agents=len(self.agents),
            active_agents=active,
            tasks_completed=sum(t.tasks_completed for t in self.agents.values()),
            avg_success_rate=avg_success,
            collaboration_score=self._calculate_collaboration_score(),
        )
    
    def _calculate_collaboration_score(self) -> float:
        """Calculate swarm collaboration score."""
        messages_count = len(self.messages)
        tasks_count = sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETED)
        
        if tasks_count == 0:
            return 0.5
        
        return min(1.0, messages_count / (tasks_count * 2))
    
    def get_orchestrator_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            "total_agents": len(self.agents),
            "active_agents": sum(1 for a in self.agents.values() if a.status == AgentStatus.BUSY),
            "idle_agents": sum(1 for a in self.agents.values() if a.status == AgentStatus.IDLE),
            "total_tasks": len(self.tasks),
            "pending_tasks": sum(1 for t in self.tasks.values() if t.status == TaskStatus.PENDING),
            "completed_tasks": sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETED),
            "failed_tasks": sum(1 for t in self.tasks.values() if t.status == TaskStatus.FAILED),
            "total_messages": len(self.messages),
        }


def get_orchestrator() -> AgentOrchestrator:
    """Get the global orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator()
    return _orchestrator


_orchestrator: Optional[AgentOrchestrator] = None