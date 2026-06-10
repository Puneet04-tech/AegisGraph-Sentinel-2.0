"""FastAPI dependency providers for lazily-accessed subsystems."""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Per-service construction locks (created on first use, not at import time)
# Only needed for services with external I/O or shared mutable init state.
# ---------------------------------------------------------------------------
_honeypot_lock: Optional[asyncio.Lock] = None
_blockchain_lock: Optional[asyncio.Lock] = None
_lateral_lock: Optional[asyncio.Lock] = None


def _get_honeypot_lock() -> asyncio.Lock:
    global _honeypot_lock
    if _honeypot_lock is None:
        _honeypot_lock = asyncio.Lock()
    return _honeypot_lock


def _get_blockchain_lock() -> asyncio.Lock:
    global _blockchain_lock
    if _blockchain_lock is None:
        _blockchain_lock = asyncio.Lock()
    return _blockchain_lock


def _get_lateral_lock() -> asyncio.Lock:
    global _lateral_lock
    if _lateral_lock is None:
        _lateral_lock = asyncio.Lock()
    return _lateral_lock


# ---------------------------------------------------------------------------
# Stateless / fast-init providers  no lock required
# ---------------------------------------------------------------------------

def get_mule_scorer():
    """Return the live PredictiveMuleScorer, constructing on first use."""
    from src.api.main import state
    service = state.services.optional_get("mule_scorer")
    if service is None:
        from src.features.predictive_mule_identification import PredictiveMuleScorer
        service = PredictiveMuleScorer()
        state.services.register_service("mule_scorer", service, replace=True)
    return service


def get_voice_analyzer():
    """Return the live VoiceStressAnalyzer, constructing on first use."""
    from src.api.main import state
    service = state.services.optional_get("voice_analyzer")
    if service is None:
        from src.features.voice_stress_analysis import VoiceStressAnalyzer
        service = VoiceStressAnalyzer()
        state.services.register_service("voice_analyzer", service, replace=True)
    return service


def get_aegis_oracle():
    """Return the live AegisOracleExplainer, constructing on first use.
    If the service has been explicitly registered as None, return None.
    """
    from src.api.main import state
    # Check if the service key exists in the container (may be None)
    if "aegis_oracle" in state.services._services:
        return state.services._services["aegis_oracle"]
    # Otherwise, use optional_get which returns None if not present
    service = state.services.optional_get("aegis_oracle")
    if service is None:
        from src.features.aegis_oracle_explainer import AegisOracleExplainer
        service = AegisOracleExplainer()
        state.services.register_service("aegis_oracle", service, replace=True)
    return service


# ---------------------------------------------------------------------------
# I/O-bound providers  lock guards against double-construction
# ---------------------------------------------------------------------------

async def get_honeypot_manager():
    """Return the live HoneypotEscrowManager, constructing on first use."""
    from src.api.main import state
    service = state.services.optional_get("honeypot_manager")
    if service is None:
        async with _get_honeypot_lock():
            service = state.services.optional_get("honeypot_manager")
            if service is None:
                from src.features.honeypot_escrow import HoneypotEscrowManager
                service = HoneypotEscrowManager()
                state.services.register_service("honeypot_manager", service, replace=True)
    return service


async def get_blockchain_manager():
    """Return the live BlockchainEvidenceManager, constructing on first use."""
    from src.api.main import state
    service = state.services.optional_get("blockchain_manager")
    if service is None:
        async with _get_blockchain_lock():
            service = state.services.optional_get("blockchain_manager")
            if service is None:
                from src.features.blockchain_evidence import BlockchainEvidenceManager
                service = BlockchainEvidenceManager()
                state.services.register_service("blockchain_manager", service, replace=True)
    return service


async def get_lateral_movement_detector():
    """Return the live LateralMovementDetector, or None if unavailable."""
    from src.api.main import state
    service = state.services.optional_get("lateral_movement_detector")
    if service is None:
        async with _get_lateral_lock():
            service = state.services.optional_get("lateral_movement_detector")
            if service is None:
                try:
                    from src.features.lateral_movement import LateralMovementDetector
                    service = LateralMovementDetector()
                    state.services.register_service(
                        "lateral_movement_detector", service, replace=True
                    )
                except Exception as exc:
                    import logging
                    logging.getLogger(__name__).debug("Lateral movement detector construction failed (optional feature): %s", exc)
                    return None  # lateral movement is optional
    return service  # may still be None if construction failed
