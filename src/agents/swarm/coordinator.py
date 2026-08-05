"""
Swarm Coordinator
AegisGraph Sentinel - Swarm lifecycle and agent coordination.

The coordinator registers heterogeneous swarm agents, dispatches simulation
tasks across them with work-stealing load balancing, and drives the complete
adversarial simulation cycle:

    attack simulation -> threat hunting -> red team validation -> feedback

Agents run concurrently in a bounded thread pool. When an agent exhausts its
own queue it steals work from the busiest sibling, which keeps a swarm of 20+
agents saturated without a central scheduler bottleneck.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from .models import (
    AgentDescriptor,
    SimulationFinding,
    SwarmAgentStatus,
    SwarmAgentType,
    SwarmReport,
    SwarmTask,
    SwarmTaskPriority,
    ThreatDiscovery,
)
from .store import ThreatIntelligenceStore, get_threat_intelligence_store

logger = logging.getLogger(__name__)

_PRIORITY_ORDER = {
    SwarmTaskPriority.CRITICAL: 0,
    SwarmTaskPriority.HIGH: 1,
    SwarmTaskPriority.MEDIUM: 2,
    SwarmTaskPriority.LOW: 3,
}


class WorkStealingCoordinator:
    """Coordination manager for the adversarial simulation swarm.

    Attributes:
        max_workers: Number of concurrent agent slots (default 32).
        store: Shared threat intelligence store.
        agents: Registered agent descriptors keyed by agent id.
        handler: Callable invoked to execute a task; the signature is
            ``handler(agent_id, task) -> dict``.
    """

    def __init__(
        self,
        max_workers: int = 32,
        store: Optional[ThreatIntelligenceStore] = None,
        handler: Optional[Callable[[str, SwarmTask], Dict[str, Any]]] = None,
    ) -> None:
        self.max_workers = max_workers
        self.store = store or get_threat_intelligence_store()
        self.agents: Dict[str, AgentDescriptor] = {}
        self._handler = handler or self._default_handler
        self._queues: Dict[str, List[SwarmTask]] = {}
        self._tasks: Dict[str, SwarmTask] = {}
        self._lock = threading.RLock()
        self._completed: List[SwarmTask] = []
        self._discoveries: List[ThreatDiscovery] = []
        self._findings: List[SimulationFinding] = []

    # ------------------------------------------------------------------
    # Agent lifecycle
    # ------------------------------------------------------------------

    def register_agent(
        self,
        agent_type: SwarmAgentType,
        capabilities: Optional[List[str]] = None,
        agent_id: Optional[str] = None,
    ) -> str:
        """Register an agent with the swarm and return its id."""
        agent_id = agent_id or f"{agent_type.value}-{uuid4().hex[:8]}"
        descriptor = AgentDescriptor(
            agent_id=agent_id,
            agent_type=agent_type,
            capabilities=capabilities or [],
        )
        with self._lock:
            self.agents[agent_id] = descriptor
            self._queues[agent_id] = []
        self.store.register_agent(descriptor)
        logger.info("Registered swarm agent %s (%s)", agent_id, agent_type.value)
        return agent_id

    def spawn_agents(self, agent_type: SwarmAgentType, count: int) -> List[str]:
        """Spawn ``count`` agents of a given type (used to scale to 20+)."""
        return [self.register_agent(agent_type) for _ in range(count)]

    def agent_count(self) -> int:
        with self._lock:
            return len(self.agents)

    def _least_loaded_agent_id(self) -> Optional[str]:
        with self._lock:
            if not self.agents:
                return None
            return min(
                self.agents,
                key=lambda aid: (
                    len(self._queues[aid]),
                    self.agents[aid].load,
                ),
            )

    # ------------------------------------------------------------------
    # Task dispatch
    # ------------------------------------------------------------------

    def submit_task(
        self,
        task_type: str,
        input_data: Optional[Dict[str, Any]] = None,
        priority: SwarmTaskPriority = SwarmTaskPriority.MEDIUM,
        preferred_agent_type: Optional[SwarmAgentType] = None,
    ) -> str:
        """Submit a task to the swarm; returns the task id."""
        task_id = f"task-{uuid4().hex[:12]}"
        task = SwarmTask(
            task_id=task_id,
            task_type=task_type,
            priority=priority,
            input_data=input_data or {},
        )
        with self._lock:
            self._tasks[task_id] = task
            agent_id = self._pick_agent(preferred_agent_type)
            if agent_id is None:
                raise RuntimeError("No agents registered in the swarm")
            task.agent_id = agent_id
            task.status = SwarmAgentStatus.WAITING
            self._queues[agent_id].append(task)
        return task_id

    def _pick_agent(self, preferred_agent_type: Optional[SwarmAgentType]) -> Optional[str]:
        if preferred_agent_type is not None:
            matches = [aid for aid, a in self.agents.items() if a.agent_type == preferred_agent_type]
            if matches:
                return min(matches, key=lambda aid: (len(self._queues[aid]), self.agents[aid].load))
        return self._least_loaded_agent_id()

    # ------------------------------------------------------------------
    # Work-stealing execution
    # ------------------------------------------------------------------

    def execute_all(self) -> None:
        """Run all queued tasks concurrently with work-stealing balancing."""
        with self._lock:
            pending = [t for t in self._tasks.values() if t.status == SwarmAgentStatus.WAITING]
        if not pending:
            return
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(self.agents))) as pool:
            futures = {}
            for task in pending:
                future = pool.submit(self._run_task_with_stealing, task.task_id)
                futures[future] = task
            for future in futures:
                future.result()
            self._apply_stealing_pass()
        logger.info("Swarm cycle executed %d tasks", len(pending))

    def _run_task_with_stealing(self, task_id: str) -> None:
        task = self._tasks[task_id]
        agent_id = task.agent_id
        if agent_id is None:
            task.status = SwarmAgentStatus.FAILED
            task.error = "No owning agent"
            return
        task.status = SwarmAgentStatus.RUNNING
        task.started_at = datetime.now(timezone.utc)
        descriptor = self.agents.get(agent_id)
        if descriptor is not None:
            descriptor.status = SwarmAgentStatus.RUNNING
            descriptor.current_task = task_id
            descriptor.load = min(1.0, descriptor.load + 0.25)
        try:
            result = self._handler(agent_id, task)
            task.result = result
            task.status = SwarmAgentStatus.COMPLETED
            task.completed_at = datetime.now(timezone.utc)
            self._collect_results(task)
        except Exception as exc:  # noqa: BLE001 - surfaced in report
            logger.exception("Task %s failed on agent %s", task_id, agent_id)
            task.status = SwarmAgentStatus.FAILED
            task.error = str(exc)
            task.completed_at = datetime.now(timezone.utc)
            if descriptor is not None:
                descriptor.failures += 1
        finally:
            if descriptor is not None:
                descriptor.tasks_processed += 1
                descriptor.load = max(0.0, descriptor.load - 0.25)
                descriptor.status = SwarmAgentStatus.IDLE
                descriptor.current_task = None
                descriptor.last_heartbeat = datetime.now(timezone.utc)
            with self._lock:
                self._completed.append(task)

    def _apply_stealing_pass(self) -> None:
        """Work-stealing load balancing pass over the swarm queues."""
        with self._lock:
            for agent_id, queue in self._queues.items():
                if not queue:
                    continue
                queue.sort(key=lambda t: _PRIORITY_ORDER[t.priority])
                overloaded = len(queue)
                if overloaded <= 1:
                    continue
                steal_count = overloaded // 2
                for _ in range(steal_count):
                    if not queue:
                        break
                    victim = queue.pop(0)
                    self._assign_task_to_least_loaded(victim)

    def _assign_task_to_least_loaded(self, task: SwarmTask) -> None:
        target = self._least_loaded_agent_id()
        if target is None:
            return
        task.agent_id = target
        self._queues[target].append(task)

    def _collect_results(self, task: SwarmTask) -> None:
        """Harvest structured results published by agent handlers."""
        result = task.result or {}
        for discovery in result.get("discoveries", []):
            if isinstance(discovery, ThreatDiscovery):
                self._discoveries.append(discovery)
                self.store.add_discovery(discovery)
        for finding in result.get("findings", []):
            if isinstance(finding, SimulationFinding):
                self._findings.append(finding)
                self.store.add_finding(finding)

    def _default_handler(self, agent_id: str, task: SwarmTask) -> Dict[str, Any]:
        return {"task_id": task.task_id, "agent_id": agent_id}

    # ------------------------------------------------------------------
    # Full simulation cycle
    # ------------------------------------------------------------------

    def run_simulation_cycle(
        self,
        attack_simulator: Any,
        threat_hunter: Any,
        red_team: Any,
        feedback_loop: Any,
        input_graph: Dict[str, Any],
    ) -> SwarmReport:
        """Execute a complete adversarial simulation cycle.

        attack simulation -> threat hunting -> red team validation -> feedback

        Args:
            attack_simulator: Attack simulator agent.
            threat_hunter: Threat hunter agent.
            red_team: Red team agent.
            feedback_loop: Feedback loop agent.
            input_graph: Entity graph supplied to the cycle.

        Returns:
            Aggregate SwarmReport of the whole cycle.
        """
        report = SwarmReport(
            report_id=f"report-{uuid4().hex[:12]}",
            started_at=datetime.now(timezone.utc),
            agent_count=self.agent_count(),
        )

        patterns = attack_simulator.generate_patterns()
        self.store.add_patterns(patterns)

        discoveries = threat_hunter.hunt(input_graph)
        for discovery in discoveries:
            self._discoveries.append(discovery)
            self.store.add_discovery(discovery)

        evasions = red_team.run_benchmark()
        blind_spots = [e for e in evasions if e.blind_spot]

        coverage = feedback_loop.compute_coverage(input_graph)
        retraining = feedback_loop.maybe_trigger_retraining(coverage)

        report.completed_at = datetime.now(timezone.utc)
        report.tasks_completed = len(self._completed) + len(patterns) + len(discoveries)
        report.tasks_failed = sum(1 for t in self._completed if t.status == SwarmAgentStatus.FAILED)
        report.discoveries = discoveries
        report.findings = list(self._findings)
        report.attack_patterns_generated = len(patterns)
        report.evasion_techniques_tested = len(evasions)
        report.blind_spots_found = len(blind_spots)
        report.retraining_triggered = retraining
        report.coverage = coverage
        return report


class SwarmCoordinator(WorkStealingCoordinator):
    """Alias preserving the swarm terminology used in the issue."""
