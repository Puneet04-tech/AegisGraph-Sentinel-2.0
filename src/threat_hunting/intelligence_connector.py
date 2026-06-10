"""
Threat Intelligence Connector Engine for AI Threat Hunting
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from .models import ThreatIndicator, IndicatorType, ThreatSeverity
from .store import ThreatHuntingStore, get_store


class ThreatIntelligenceConnector:
    """Connector to lookup indicators in external threat intelligence databases."""

    def __init__(self, store: Optional[ThreatHuntingStore] = None):
        self.store = store or get_store()
        self.malicious_ips = {
            "198.51.100.42",
            "203.0.113.100",
            "185.220.101.5",  # Common mock Tor Exit Nodes
            "185.220.101.6",
        }
        self.malicious_domains = {
            "attacker.com",
            "fraud-transfer.net",
            "mule-network.org",
        }

    def check_ip(self, ip_address: str) -> Optional[ThreatIndicator]:
        """Check if an IP address is flagged in threat intelligence databases."""
        if ip_address in self.malicious_ips:
            ind = ThreatIndicator(
                indicator_type=IndicatorType.IP,
                value=ip_address,
                description="Threat Intel Match: IP registered as known malicious actor or Tor node",
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                attributes={"source": "abuseipdb_mock", "category": "tor_exit_node"},
            )
            self.store.register_indicator(ind)
            return ind
        return None

    def check_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """Check if a domain is flagged in threat intelligence databases."""
        if domain in self.malicious_domains:
            ind = ThreatIndicator(
                indicator_type=IndicatorType.DOMAIN,
                value=domain,
                description="Threat Intel Match: Domain matches known command-and-control server",
                severity=ThreatSeverity.CRITICAL,
                confidence=0.9,
                attributes={"source": "phishtank_mock", "category": "malware_distribution"},
            )
            self.store.register_indicator(ind)
            return ind
        return None
