"""Security Exchange Service"""
from typing import Any, Dict, List, Optional
from .models import ExchangePartner, SharedIntelligence, DataGovernanceRule
from .federation import FederationLayer

class SecurityExchangeService:
    """Main service for Security Data Exchange"""
    
    def __init__(self) -> None:
        self.federation = FederationLayer()
    
    def add_partner(
        self,
        name: str,
        organization_type: str,
        country: str,
        trust_score: float = 0.5,
        data_classification: str = "INTERNAL"
    ) -> Dict[str, Any]:
        """Add a partner to the exchange"""
        from .models import OrganizationType
        partner = ExchangePartner(
            partner_id=f"partner-{name.lower().replace(' ', '-')}",
            name=name,
            organization_type=OrganizationType(organization_type),
            country=country,
            verified=False,
            trust_score=trust_score,
            data_classification=data_classification
        )
        self.federation.add_partner(partner)
        return partner.to_dict()
    
    def get_partner(self, partner_id: str) -> Optional[Dict[str, Any]]:
        """Get a partner by ID"""
        partner = self.federation.get_partner(partner_id)
        return partner.to_dict() if partner else None
    
    def get_all_partners(self) -> List[Dict[str, Any]]:
        """Get all partners"""
        return [p.to_dict() for p in self.federation.partners.values()]
    
    def get_partners_by_type(self, org_type: str) -> List[Dict[str, Any]]:
        """Get partners by organization type"""
        from .models import OrganizationType
        return [p.to_dict() for p in self.federation.get_partners_by_type(OrganizationType(org_type))]
    
    def share_intelligence(
        self,
        title: str,
        description: str,
        intelligence_type: str,
        from_partner: str,
        to_partners: List[str],
        classification: str,
        threat_indicators: List[str],
        expires_in_days: int = 30
    ) -> Optional[Dict[str, Any]]:
        """Share intelligence with partners"""
        share = self.federation.share_intelligence(
            title=title,
            description=description,
            intelligence_type=intelligence_type,
            from_partner=from_partner,
            to_partners=to_partners,
            classification=classification,
            threat_indicators=threat_indicators,
            expires_in_days=expires_in_days
        )
        return share.to_dict() if share else None
    
    def search_intelligence(
        self,
        query: Optional[str] = None,
        intelligence_type: Optional[str] = None,
        from_partner: Optional[str] = None,
        classification: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Search shared intelligence"""
        results = self.federation.search_intelligence(
            query=query,
            intelligence_type=intelligence_type,
            from_partner=from_partner,
            classification=classification
        )
        return [r.to_dict() for r in results]
    
    def get_shared_intelligence(self, share_id: str) -> Optional[Dict[str, Any]]:
        """Get shared intelligence by ID"""
        share = self.federation.shares.get(share_id)
        return share.to_dict() if share else None
    
    def get_federation_stats(self) -> Dict[str, Any]:
        """Get federation statistics"""
        return self.federation.get_federation_stats()
    
    def get_exchange_dashboard(self) -> Dict[str, Any]:
        """Get exchange dashboard data"""
        stats = self.federation.get_federation_stats()
        recent_shares = self.federation.search_intelligence()[:10]
        
        return {
            "federation_stats": stats,
            "recent_shares": [s.to_dict() for s in recent_shares],
            "total_intelligence_shared": stats["total_shares"]
        }


# Global service instance
_exchange_service: Optional[SecurityExchangeService] = None

def get_exchange_service() -> SecurityExchangeService:
    """Get the global service instance"""
    global _exchange_service
    if _exchange_service is None:
        _exchange_service = SecurityExchangeService()
    return _exchange_service