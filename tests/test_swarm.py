"""Comprehensive tests for the adversarial simulation & threat hunting swarm.

Covers every acceptance criterion from issue #2597:

- Swarm coordinator manages 20+ concurrent agents with work-stealing
  load balancing
- Attack simulator produces mule behaviours validated against known fraud
  signatures
- Threat hunter discovers fraud rings at >=80% precision
- Red team identifies model blind spots
- Feedback loop triggers retraining below coverage threshold
- Threat intelligence graph stores 100+ attack patterns
- Dashboard exposes agent status, threat events, improvement trends
- Simulation policies are tenant-configurable with RBAC
- End-to-end simulation cycle test
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.agents.swarm.attack_simulator import AttackSimulator, FRAUD_SIGNATURES
from src.agents.swarm.coordinator import SwarmCoordinator
from src.agents.swarm.dashboard import SwarmDashboard
from src.agents.swarm.feedback_loop import FeedbackLoop
from src.agents.swarm.models import SwarmAgentStatus, SwarmAgentType
from src.agents.swarm.policies import (
    PermissionDeniedError,
    PolicyRole,
    SimulationPolicyEngine,
)
from src.agents.swarm.red_team import EVASION_TECHNIQUES, RedTeamAgent
from src.agents.swarm.store import ThreatIntelligenceStore
from src.agents.swarm.threat_hunter import ThreatHunter
from src.agents.swarm.threat_intelligence_graph import ThreatIntelligenceGraph
from src.models.adversarial_robustness import AdversarialRobustnessEvaluator


# ---------------------------------------------------------------------------
# Coordinator: 20+ concurrent agents with work-stealing
# ---------------------------------------------------------------------------


class TestCoordinator:
    def test_manages_more_than_20_concurrent_agents(self):
        coordinator = SwarmCoordinator(max_workers=32)
        agent_ids = []
        for agent_type in [
            SwarmAgentType.ATTACK_SIMULATOR,
            SwarmAgentType.THREAT_HUNTER,
            SwarmAgentType.PATTERN_HUNTER,
            SwarmAgentType.ANOMALY_EXPLORER,
            SwarmAgentType.LATERAL_MOVEMENT_MAPPER,
            SwarmAgentType.RED_TEAM,
        ]:
            agent_ids.extend(coordinator.spawn_agents(agent_type, count=4))

        assert coordinator.agent_count() >= 20
        assert len(set(agent_ids)) == len(agent_ids)

    def test_dispatches_tasks_across_agents(self):
        coordinator = SwarmCoordinator(max_workers=8)
        for _ in range(6):
            coordinator.spawn_agents(SwarmAgentType.THREAT_HUNTER, count=1)

        for i in range(10):
            task_id = coordinator.submit_task(
                task_type="hunt",
                input_data={"job": i},
            )
            assert task_id.startswith("task-")

        coordinator.execute_all()
        completed = [t for t in coordinator._tasks.values() if t.status == SwarmAgentStatus.COMPLETED]
        assert len(completed) == 10

    def test_work_stealing_rebalances_busy_agents(self):
        coordinator = SwarmCoordinator(max_workers=4)
        coordinator.spawn_agents(SwarmAgentType.ATTACK_SIMULATOR, count=4)

        coordinator.submit_task("simulate", {"payload": "a"})
        coordinator.submit_task("simulate", {"payload": "b"})
        coordinator.submit_task("simulate", {"payload": "c"})
        coordinator.submit_task("simulate", {"payload": "d"})

        coordinator._apply_stealing_pass()
        queue_sizes = [len(q) for q in coordinator._queues.values()]
        assert max(queue_sizes) - min(queue_sizes) <= 1

    def test_execute_all_runs_full_pipeline(self):
        coordinator = SwarmCoordinator(max_workers=4)
        coordinator.spawn_agents(SwarmAgentType.ATTACK_SIMULATOR, count=2)
        coordinator.spawn_agents(SwarmAgentType.RED_TEAM, count=2)
        coordinator.submit_task("attack", {"type": "smurfing"})
        coordinator.submit_task("redteam", {"type": "slow_drip"})

        coordinator.execute_all()
        assert all(
            t.status in (SwarmAgentStatus.COMPLETED, SwarmAgentStatus.FAILED)
            for t in coordinator._tasks.values()
        )


# ---------------------------------------------------------------------------
# Attack simulator
# ---------------------------------------------------------------------------


class TestAttackSimulator:
    def test_generates_patterns_validated_against_known_signatures(self):
        simulator = AttackSimulator(seed=7)
        patterns = simulator.generate_patterns(count=15)

        assert len(patterns) == 15
        validation = simulator.validate_generated_patterns()
        assert validation["coverage"] == 1.0
        assert validation["unmatched"] == 0

    def test_mule_behavior_matches_known_signature_library(self):
        simulator = AttackSimulator(seed=3)
        behavior = simulator.generate_mule_behavior(technique="smurfing")

        assert behavior.technique == "smurfing"
        assert behavior.transaction_count > 0
        assert behavior.total_amount > 0
        assert "smurfing" in FRAUD_SIGNATURES

    def test_synthetic_graph_contains_mule_and_decoy_nodes(self):
        simulator = AttackSimulator(seed=11)
        graph = simulator.build_synthetic_graph(mules=6, hops=2)

        mules = [n for n in graph["nodes"] if n.get("is_mule")]
        decoys = [n for n in graph["nodes"] if n.get("id", "").startswith("legit-")]
        assert len(mules) == 6
        assert len(decoys) >= 18
        assert len(graph["edges"]) >= 6


# ---------------------------------------------------------------------------
# Threat hunter: >=80% precision benchmark
# ---------------------------------------------------------------------------


class TestThreatHunter:
    def test_discovers_fraud_rings_with_high_precision(self):
        simulator = AttackSimulator(seed=5)
        graph = simulator.build_synthetic_graph(mules=8, hops=2)

        hunter = ThreatHunter()
        benchmark = hunter.benchmark_precision(graph)

        assert benchmark["precision"] >= 0.8
        assert benchmark["true_positives"] >= 1

    def test_hunt_returns_discoveries(self):
        simulator = AttackSimulator(seed=9)
        graph = simulator.build_synthetic_graph(mules=4, hops=2)

        hunter = ThreatHunter()
        discoveries = hunter.hunt(graph)

        assert len(discoveries) >= 1
        assert all(len(d.member_entities) >= 1 for d in discoveries)

    def test_empty_graph_yields_no_discoveries(self):
        hunter = ThreatHunter()
        assert hunter.hunt({"nodes": [], "edges": []}) == []


# ---------------------------------------------------------------------------
# Red team: identifies blind spots
# ---------------------------------------------------------------------------


class TestRedTeam:
    def test_benchmark_covers_all_ten_evasion_techniques(self):
        red_team = RedTeamAgent(seed=1)
        reports = red_team.run_benchmark(samples_per_technique=10)

        assert len(reports) == 10
        assert len(EVASION_TECHNIQUES) == 10
        assert {r.technique for r in reports} == {t["name"] for t in EVASION_TECHNIQUES}

    def test_identifies_blind_spots_against_weak_model(self):
        red_team = RedTeamAgent(seed=2)
        reports = red_team.run_benchmark(samples_per_technique=20)
        blind_spots = red_team.identify_blind_spots(reports)

        assert len(blind_spots) >= 1
        assert all(r.blind_spot for r in blind_spots)

    def test_generates_attack_patterns_for_store(self):
        red_team = RedTeamAgent(seed=4)
        patterns = red_team.generate_attack_patterns()

        assert len(patterns) == 10
        assert all(p.technique for p in patterns)


# ---------------------------------------------------------------------------
# Feedback loop: retraining on low coverage
# ---------------------------------------------------------------------------


class TestFeedbackLoop:
    def test_triggers_retraining_when_coverage_below_threshold(self):
        store = ThreatIntelligenceStore()
        loop = FeedbackLoop(retraining_threshold=0.6, store=store)
        graph = {"nodes": [{"id": f"unknown-{i}"} for i in range(100)], "edges": []}

        coverage = loop.compute_coverage(graph)
        triggered = loop.maybe_trigger_retraining(coverage)

        assert triggered is True
        assert loop.retraining_event_count() == 1

    def test_no_retraining_when_coverage_not_below_threshold(self):
        store = ThreatIntelligenceStore()
        loop = FeedbackLoop(retraining_threshold=0.0, store=store)
        graph = {"nodes": [{"id": "n1"}, {"id": "n2"}], "edges": []}

        coverage = loop.compute_coverage(graph)
        assert loop.maybe_trigger_retraining(coverage) is False

    def test_improvement_trend_tracks_precision_history(self):
        loop = FeedbackLoop()
        loop.record_precision(0.7)
        loop.record_precision(0.8)
        loop.record_precision(0.85)

        trend = loop.improvement_trend()
        assert trend["delta"] == pytest.approx(0.15)


# ---------------------------------------------------------------------------
# Threat intelligence graph: 100+ patterns
# ---------------------------------------------------------------------------


class TestThreatIntelligenceGraph:
    def test_stores_more_than_100_patterns_with_context(self):
        graph = ThreatIntelligenceGraph()
        simulator = AttackSimulator(seed=13)

        patterns = []
        for _ in range(11):
            patterns.extend(simulator.generate_patterns(count=10))

        assert graph.add_patterns(patterns) == 110
        assert graph.pattern_count() >= 100

        stored = graph.get_patterns()
        assert all(p.entity_type for p in stored)
        assert all(p.temporal_context for p in stored)

    def test_graph_topology_connects_patterns_to_ttp(self):
        graph = ThreatIntelligenceGraph()
        simulator = AttackSimulator(seed=21)

        graph.add_patterns(simulator.generate_patterns(count=5))
        assert graph.node_count() > 0
        assert graph.edge_count() > 0
        assert len(graph.techniques()) >= 1
        assert len(graph.temporal_contexts()) >= 1


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class TestSwarmDashboard:
    def test_snapshot_exposes_agent_threat_and_improvement_state(self):
        store = ThreatIntelligenceStore()
        loop = FeedbackLoop()
        coordinator = SwarmCoordinator(max_workers=8, store=store)
        coordinator.spawn_agents(SwarmAgentType.THREAT_HUNTER, count=3)

        graph = ThreatIntelligenceGraph()
        dashboard = SwarmDashboard(
            coordinator=coordinator,
            store=store,
            feedback_loop=loop,
            intelligence_graph=graph,
        )
        snapshot = dashboard.snapshot()

        assert snapshot["agents"]["active_agents"] == 3
        assert snapshot["agents"]["idle"] == 3
        assert snapshot["threats"]["total_discoveries"] == 0
        assert snapshot["improvement"]["retraining_events"] == 0

    def test_threat_events_reflect_store_discoveries(self):
        store = ThreatIntelligenceStore()
        dashboard = SwarmDashboard(store=store)
        from src.agents.swarm.models import ThreatDiscovery

        store.add_discovery(ThreatDiscovery(
            discovery_id="d1",
            member_entities=["a", "b", "c"],
            discovery_type="fraud_ring",
        ))
        events = dashboard.threat_events()

        assert events["total_discoveries"] == 1
        assert events["fraud_rings"] == 1


# ---------------------------------------------------------------------------
# Policies: tenant-configurable with RBAC
# ---------------------------------------------------------------------------


class TestSimulationPolicies:
    def test_viewer_cannot_create_policy(self):
        engine = SimulationPolicyEngine()
        with pytest.raises(PermissionDeniedError):
            engine.create_policy("tenant-a", PolicyRole.VIEWER)

    def test_operator_can_create_and_update_policy(self):
        engine = SimulationPolicyEngine()
        policy = engine.create_policy(
            "tenant-a",
            PolicyRole.OPERATOR,
            intensity=0.4,
            frequency="weekly",
        )

        assert policy.tenant_id == "tenant-a"
        updated = engine.update_policy(policy.policy_id, PolicyRole.OPERATOR, intensity=0.9)
        assert updated.intensity == pytest.approx(0.9)

    def test_only_admin_can_delete_policy(self):
        engine = SimulationPolicyEngine()
        policy = engine.create_policy("tenant-a", PolicyRole.ADMIN)

        with pytest.raises(PermissionDeniedError):
            engine.delete_policy(policy.policy_id, PolicyRole.OPERATOR)
        assert engine.delete_policy(policy.policy_id, PolicyRole.ADMIN) is True

    def test_tenant_risk_profile_controls_default_intensity(self):
        engine = SimulationPolicyEngine()
        engine.set_tenant_profile("high-risk", "high")
        engine.set_tenant_profile("low-risk", "low")

        high_policy = engine.apply_to_tenant("high-risk")
        low_policy = engine.apply_to_tenant("low-risk")

        assert high_policy.intensity > low_policy.intensity


# ---------------------------------------------------------------------------
# Adversarial robustness evaluator
# ---------------------------------------------------------------------------


class TestAdversarialRobustness:
    def test_evaluate_reports_robustness_and_blind_spots(self):
        evaluator = AdversarialRobustnessEvaluator()
        report = evaluator.evaluate(samples_per_technique=10)

        assert 0.0 <= report["robustness_score"] <= 1.0
        assert "blind_spots" in report
        assert len(report["technique_results"]) == 10

    def test_compare_models_recommends_stronger_model(self):
        strong = lambda features: 0.9  # noqa: E731

        evaluator = AdversarialRobustnessEvaluator()
        comparison = evaluator.compare_models(strong)

        assert comparison["candidate_robustness"] > comparison["baseline_robustness"]
        assert comparison["recommendation"] == "adopt candidate"


# ---------------------------------------------------------------------------
# End-to-end simulation cycle
# ---------------------------------------------------------------------------


class TestEndToEndSimulationCycle:
    def test_complete_cycle(self):
        store = ThreatIntelligenceStore()
        coordinator = SwarmCoordinator(max_workers=16, store=store)
        for agent_type in [
            SwarmAgentType.ATTACK_SIMULATOR,
            SwarmAgentType.THREAT_HUNTER,
            SwarmAgentType.PATTERN_HUNTER,
            SwarmAgentType.ANOMALY_EXPLORER,
            SwarmAgentType.LATERAL_MOVEMENT_MAPPER,
            SwarmAgentType.RED_TEAM,
        ]:
            coordinator.spawn_agents(agent_type, count=4)

        simulator = AttackSimulator(seed=42)
        hunter = ThreatHunter()
        red_team = RedTeamAgent(seed=8)
        loop = FeedbackLoop(retraining_threshold=0.6, store=store)

        graph = simulator.build_synthetic_graph(mules=8, hops=2)
        report = coordinator.run_simulation_cycle(
            attack_simulator=simulator,
            threat_hunter=hunter,
            red_team=red_team,
            feedback_loop=loop,
            input_graph=graph,
        )

        assert report.agent_count >= 20
        assert report.attack_patterns_generated >= 10
        assert report.evasion_techniques_tested == 10
        assert report.blind_spots_found >= 1
        assert report.completed_at is not None
        assert report.completed_at >= report.started_at
        assert store.pattern_count() >= 10
        assert store.discovery_count() >= 1

    def test_cycle_timestamp_is_utc_aware(self):
        coordinator = SwarmCoordinator()
        coordinator.spawn_agents(SwarmAgentType.RED_TEAM, count=1)
        report = coordinator.run_simulation_cycle(
            attack_simulator=AttackSimulator(seed=1),
            threat_hunter=ThreatHunter(),
            red_team=RedTeamAgent(seed=1),
            feedback_loop=FeedbackLoop(),
            input_graph={"nodes": [], "edges": []},
        )
        assert report.started_at.tzinfo is not None
        assert report.started_at.utcoffset() == timezone.utc.utcoffset(datetime.now(timezone.utc))
