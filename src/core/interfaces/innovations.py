"""Service boundaries for modular threat detection and reporting innovations."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol


class VoiceStressAnalyzerService(Protocol):
    """Protocol for analyzing behavioral stress via voice metrics."""

    def analyze_voice(self, audio_file: str, sample_rate: int = 16000) -> Dict[str, Any]:
        ...


class PredictiveMuleScorerService(Protocol):
    """Protocol for evaluating account opening profiles for mule risk pre-transaction."""

    def score_account_opening(self, account_data: Optional[Any] = None, **kwargs) -> Dict[str, Any]:
        ...


class HoneypotEscrowManagerService(Protocol):
    """Protocol for active mitigation and tracing via honeypot escrow accounts."""

    def should_activate_honeypot(
        self,
        transaction_id: str,
        source_account: str,
        target_account: str,
        amount: float,
        risk_score: float,
    ) -> bool:
        ...

    def activate_honeypot(
        self,
        transaction_id: str,
        source_account: str,
        target_account: str,
        amount: float,
        currency: str,
        risk_score: float,
        fraud_indicators: List[str],
    ) -> Dict[str, Any]:
        ...

    def get_active_honeypots(self) -> List[Dict[str, Any]]:
        ...

    def get_statistics(self) -> Dict[str, Any]:
        ...


class BlockchainEvidenceManagerService(Protocol):
    """Protocol for sealing evidence securely and verifying ledger integrity."""

    def seal_evidence(
        self,
        transaction_id: str,
        source_account: str,
        target_account: str,
        amount: float,
        risk_score: Optional[float] = None,
        decision: Optional[str] = None,
        confidence: Optional[float] = None,
        breakdown: Optional[Dict[str, float]] = None,
        explanation: str = "",
        fraud_patterns: Optional[List[str]] = None,
        risk_result: Optional[Dict[str, Any]] = None,
    ) -> Any:
        ...

    def verify_evidence(self, evidence_id: str, block_number: int) -> Dict[str, bool]:
        ...


class AegisOracleExplainerService(Protocol):
    """Protocol for generating explainable reasoning and regulatory reports."""

    def generate_explanation(
        self,
        transaction: Optional[Dict[str, Any]] = None,
        risk_result: Optional[Dict[str, Any]] = None,
        detail_level: str = "medium",
        **kwargs,
    ) -> Dict[str, Any]:
        ...


class LateralMovementDetectorService(Protocol):
    """Protocol for detecting suspicious central pivoting in graph topologies."""

    def update_graph(self, src_account: str, dst_account: str) -> None:
        ...

    def analyze_account(self, account_id: str) -> tuple[float, bool]:
        ...
