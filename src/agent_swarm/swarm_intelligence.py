"""
Swarm Intelligence Layer
Enables emergent behavior and collaboration between agents.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4
import random

from .models import AgentType, TaskPriority
from .orchestrator import AgentOrchestrator, get_orchestrator


class SwarmIntelligenceLayer:
    """Layer for emergent swarm intelligence."""
    
    def __init__(self, orchestrator: Optional[AgentOrchestrator] = None):
        self.orchestrator = orchestrator or get_orchestrator()
        self.behavior_patterns: Dict[str, List[str]] = {}
        self.learning_history: List[Dict[str, Any]] = []
    
    def orchestrate_task(self, task_type: str, task_data: Dict[str, Any]) -> str:
        """Orchestrate a task across the swarm."""
        best_agent = self._select_best_agent(task_type, task_data)
        
        if not best_agent:
            return self.orchestrator.create_task(
                task_type=task_type,
                description=f"Task for {task_type}",
                priority=TaskPriority.MEDIUM,
                input_data=task_data,
            )
        
        task_id = self.orchestrator.create_task(
            task_type=task_type,
            description=f"Task for {task_type}",
            priority=TaskPriority.MEDIUM,
            input_data=task_data,
        )
        
        self.orchestrator.assign_task(task_id, best_agent.agent_id)
        
        return task_id
    
    def _select_best_agent(self, task_type: str, task_data: Dict[str, Any]) -> Optional[Any]:
        """Select the best agent for a task."""
        agents = self.orchestrator.get_available_agents()
        
        if not agents:
            return None
        
        scored_agents = []
        for agent in agents:
            score = self._calculate_agent_score(agent, task_type, task_data)
            scored_agents.append((agent, score))
        
        scored_agents.sort(key=lambda x: x[1], reverse=True)
        
        return scored_agents[0][0] if scored_agents else None
    
    def _calculate_agent_score(
        self,
        agent: Any,
        task_type: str,
        task_data: Dict[str, Any],
    ) -> float:
        """Calculate agent suitability score."""
        score = 0.5
        
        capabilities_lower = [c.lower() for c in agent.capabilities]
        task_type_lower = task_type.lower()
        
        for cap in capabilities_lower:
            if cap in task_type_lower:
                score += 0.3
            elif task_type_lower in cap:
                score += 0.2
        
        score += agent.success_rate * 0.3
        
        score += min(1.0, agent.tasks_completed / 100) * 0.2
        
        return min(1.0, score)
    
    def detect_emergent_behavior(self) -> List[str]:
        """Detect emergent behaviors in the swarm."""
        behaviors = []
        
        recent_messages = len(self.orchestrator.messages)
        if recent_messages > 10:
            behaviors.append("HIGH_COLLABORATION")
        
        completed_tasks = sum(
            1 for t in self.orchestrator.tasks.values()
            if t.status.name == "COMPLETED"
        )
        
        if completed_tasks > 5:
            behaviors.append("TASK_CASCADE")
        
        active_agents = sum(
            1 for a in self.orchestrator.agents.values()
            if a.status.name == "BUSY"
        )
        
        if active_agents > len(self.orchestrator.agents) * 0.7:
            behaviors.append("SURGE_DETECTED")
        
        return behaviors
    
    def learn_from_outcome(
        self,
        task_id: str,
        success: bool,
        outcome: Dict[str, Any],
    ) -> None:
        """Learn from task outcome."""
        task = self.orchestrator.tasks.get(task_id)
        if not task:
            return
        
        learning = {
            "task_id": task_id,
            "task_type": task.task_type,
            "success": success,
            "agent_id": task.assigned_agent,
            "outcome": outcome,
            "learned_at": datetime.now(timezone.utc).isoformat(),
        }
        
        self.learning_history.append(learning)
        
        if len(self.learning_history) > 100:
            self.learning_history = self.learning_history[-100:]
    
    def get_intelligence_report(self) -> Dict[str, Any]:
        """Get comprehensive intelligence report."""
        return {
            "swarm_id": str(uuid4()),
            "total_agents": len(self.orchestrator.agents),
            "emergent_behaviors": self.detect_emergent_behavior(),
            "learning_opportunities": len(self.learning_history),
            "performance_metrics": {
                "avg_success_rate": self._calculate_avg_success_rate(),
                "collaboration_efficiency": self._calculate_collaboration_efficiency(),
            },
            "recommendations": self._generate_recommendations(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    
    def _calculate_avg_success_rate(self) -> float:
        """Calculate average success rate."""
        if not self.orchestrator.agents:
            return 0.0
        
        return sum(a.success_rate for a in self.orchestrator.agents.values()) / len(self.orchestrator.agents)
    
    def _calculate_collaboration_efficiency(self) -> float:
        """Calculate collaboration efficiency."""
        total_tasks = len(self.orchestrator.tasks)
        if total_tasks == 0:
            return 0.0
        
        completed = sum(1 for t in self.orchestrator.tasks.values() if t.status.name == "COMPLETED")
        return completed / total_tasks
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations for swarm optimization."""
        recommendations = []
        
        idle_count = sum(1 for a in self.orchestrator.agents.values() if a.status.name == "IDLE")
        total_agents = len(self.orchestrator.agents)
        
        if idle_count > total_agents * 0.5:
            recommendations.append("Consider scaling down idle agents")
        
        failed_count = sum(1 for t in self.orchestrator.tasks.values() if t.status.name == "FAILED")
        if failed_count > 5:
            recommendations.append("Investigate high failure rate")
        
        if self._calculate_avg_success_rate() < 0.7:
            recommendations.append("Review agent training and capabilities")
        
        return recommendations


def get_swarm_intelligence() -> SwarmIntelligenceLayer:
    """Get the global swarm intelligence instance."""
    global _swarm_intelligence
    if _swarm_intelligence is None:
        _swarm_intelligence = SwarmIntelligenceLayer()
    return _swarm_intelligence


_swarm_intelligence: Optional[SwarmIntelligenceLayer] = None