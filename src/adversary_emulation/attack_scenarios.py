"""Attack Scenario Definitions for Adversary Emulation"""
from typing import List, Dict, Any
from enum import Enum

class MITRETactics(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"

class AttackScenario:
    """Attack scenario definition"""
    def __init__(
        self,
        scenario_id: str,
        name: str,
        description: str,
        tactics: List[MITRETactics],
        techniques: List[str],
        severity: str = "HIGH"
    ):
        self.scenario_id = scenario_id
        self.name = name
        self.description = description
        self.tactics = tactics
        self.techniques = techniques
        self.severity = severity
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "tactics": [t.value for t in self.tactics],
            "techniques": self.techniques,
            "severity": self.severity
        }
    
    @classmethod
    def get_predefined_scenarios(cls) -> List["AttackScenario"]:
        """Get predefined attack scenarios"""
        return [
            cls(
                scenario_id="APT29-sim",
                name="APT29 Simulation",
                description="Simulate APT29 nation-state attack patterns",
                tactics=[MITRETactics.RECONNAISSANCE, MITRETactics.INITIAL_ACCESS, MITRETactics.CREDENTIAL_ACCESS],
                techniques=["T1595", "T1566", "T1003"],
                severity="CRITICAL"
            ),
            cls(
                scenario_id="ransomware-sim",
                name="Ransomware Attack",
                description="Simulate ransomware attack chain",
                tactics=[MITRETactics.INITIAL_ACCESS, MITRETactics.EXECUTION, MITRETactics.IMPACT],
                techniques=["T1566", "T1059", "T1486"],
                severity="CRITICAL"
            ),
            cls(
                scenario_id="insider-threat-sim",
                name="Insider Threat",
                description="Simulate insider threat scenarios",
                tactics=[MITRETactics.CREDENTIAL_ACCESS, MITRETactics.EXFILTRATION],
                techniques=["T1078", "T1041"],
                severity="HIGH"
            )
        ]