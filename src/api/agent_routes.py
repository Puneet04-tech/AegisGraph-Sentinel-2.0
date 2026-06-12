"""
Agent Swarm API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from src.agent_swarm import (
    AgentOrchestrator,
    get_orchestrator,
    SwarmIntelligenceLayer,
    get_swarm_intelligence,
    AgentType,
    TaskPriority,
    get_specialized_agent,
)


router = APIRouter(prefix="/api/v1/agents", tags=["agent-swarm"])


class AgentCreateRequest(BaseModel):
    """Request to create an agent."""
    agent_type: str
    name: str
    capabilities: Optional[List[str]] = None


class TaskCreateRequest(BaseModel):
    """Request to create a task."""
    task_type: str
    description: str
    priority: str = "MEDIUM"
    input_data: Optional[Dict[str, Any]] = None


class TaskAssignRequest(BaseModel):
    """Request to assign a task."""
    task_id: str
    agent_id: str


class TaskCompleteRequest(BaseModel):
    """Request to complete a task."""
    task_id: str
    output_data: Optional[Dict[str, Any]] = None


class MessageRequest(BaseModel):
    """Request to send a message."""
    from_agent: str
    to_agent: str
    message_type: str
    content: Dict[str, Any]
    correlation_id: Optional[str] = None


def verify_api_key(x_api_key: str = Header(None)) -> str:
    """Verify API key."""
    if x_api_key != "SUPER_ADMIN":
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "module": "agent_swarm",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/stats")
async def get_stats(api_key: str = Header(None)):
    """Get agent swarm statistics."""
    verify_api_key(api_key)
    orchestrator = get_orchestrator()
    return {"stats": orchestrator.get_orchestrator_stats()}


@router.get("/agents")
async def list_agents(
    agent_type: Optional[str] = None,
    status: Optional[str] = None,
    api_key: str = Header(None),
):
    """List all agents."""
    verify_api_key(api_key)
    orchestrator = get_orchestrator()
    
    agents = list(orchestrator.agents.values())
    
    if agent_type:
        agents = [a for a in agents if a.agent_type.value == agent_type]
    
    if status:
        agents = [a for a in agents if a.status.value == status]
    
    return {
        "count": len(agents),
        "agents": [a.to_dict() for a in agents],
    }


@router.post("/agents")
async def create_agent(
    request: AgentCreateRequest,
    api_key: str = Header(None),
):
    """Create a new agent."""
    verify_api_key(api_key)
    orchestrator = get_orchestrator()
    
    agent_type = AgentType(request.agent_type)
    agent_id = orchestrator.register_agent(
        agent_type=agent_type,
        name=request.name,
        capabilities=request.capabilities,
    )
    
    return {
        "agent_id": agent_id,
        "status": "created",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/agents/{agent_id}")
async def get_agent(
    agent_id: str,
    api_key: str = Header(None),
):
    """Get agent by ID."""
    verify_api_key(api_key)
    orchestrator = get_orchestrator()
    
    agent = orchestrator.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {"agent": agent.to_dict()}


@router.get("/agents/{agent_id}/messages")
async def get_agent_messages(
    agent_id: str,
    api_key: str = Header(None),
):
    """Get messages for an agent."""
    verify_api_key(api_key)
    orchestrator = get_orchestrator()
    
    messages = orchestrator.get_agent_messages(agent_id)
    
    return {
        "agent_id": agent_id,
        "count": len(messages),
        "messages": [
            {
                "message_id": m.message_id,
                "from": m.from_agent,
                "to": m.to_agent,
                "type": m.message_type,
                "timestamp": m.timestamp.isoformat(),
            }
            for m in messages
        ],
    }


@router.get("/tasks")
async def list_tasks(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    api_key: str = Header(None),
):
    """List all tasks."""
    verify_api_key(api_key)
    orchestrator = get_orchestrator()
    
    tasks = list(orchestrator.tasks.values())
    
    if status:
        tasks = [t for t in tasks if t.status.value == status]
    
    if priority:
        tasks = [t for t in tasks if t.priority.value == priority]
    
    return {
        "count": len(tasks),
        "tasks": [t.to_dict() for t in tasks],
    }


@router.post("/tasks")
async def create_task(
    request: TaskCreateRequest,
    api_key: str = Header(None),
):
    """Create a new task."""
    verify_api_key(api_key)
    orchestrator = get_orchestrator()
    
    priority = TaskPriority(request.priority)
    task_id = orchestrator.create_task(
        task_type=request.task_type,
        description=request.description,
        priority=priority,
        input_data=request.input_data,
    )
    
    return {
        "task_id": task_id,
        "status": "created",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/tasks/assign")
async def assign_task(
    request: TaskAssignRequest,
    api_key: str = Header(None),
):
    """Assign a task to an agent."""
    verify_api_key(api_key)
    orchestrator = get_orchestrator()
    
    success = orchestrator.assign_task(request.task_id, request.agent_id)
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to assign task")
    
    return {
        "task_id": request.task_id,
        "agent_id": request.agent_id,
        "status": "assigned",
    }


@router.post("/tasks/complete")
async def complete_task(
    request: TaskCompleteRequest,
    api_key: str = Header(None),
):
    """Complete a task."""
    verify_api_key(api_key)
    orchestrator = get_orchestrator()
    
    success = orchestrator.complete_task(request.task_id, request.output_data)
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to complete task")
    
    return {
        "task_id": request.task_id,
        "status": "completed",
    }


@router.post("/messages")
async def send_message(
    request: MessageRequest,
    api_key: str = Header(None),
):
    """Send a message between agents."""
    verify_api_key(api_key)
    orchestrator = get_orchestrator()
    
    message_id = orchestrator.send_message(
        from_agent=request.from_agent,
        to_agent=request.to_agent,
        message_type=request.message_type,
        content=request.content,
        correlation_id=request.correlation_id,
    )
    
    return {
        "message_id": message_id,
        "status": "sent",
    }


@router.get("/swarm/intelligence")
async def get_swarm_intelligence_report(api_key: str = Header(None)):
    """Get swarm intelligence report."""
    verify_api_key(api_key)
    swarm = get_swarm_intelligence()
    return swarm.get_intelligence_report()


@router.get("/swarm/behaviors")
async def get_emergent_behaviors(api_key: str = Header(None)):
    """Get emergent behaviors detected."""
    verify_api_key(api_key)
    swarm = get_swarm_intelligence()
    return {
        "behaviors": swarm.detect_emergent_behavior(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }