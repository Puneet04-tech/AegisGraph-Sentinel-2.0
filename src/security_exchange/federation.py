"""Security Exchange Federation Layer"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime, timedelta
from .models import (
    ExchangePartner, SharedIntelligence, DataGovernanceRule,
    OrganizationType, DataClassification, ShareStatus
)

class FederationLayer:
    """Cross-border intelligence federation layer"""
    
    def __init__(self) -> None:
        self.partners: Dict[str, ExchangePartner] = {}
        self.shares: Dict[str, SharedIntelligence] = {}
        self.governance_rules: Dict[str, DataGovernanceRule] = {}
        self._init_sample_partners()
    
    def _init_sample_partners(self) -> None:
        """Initialize sample federation partners"""
        sample_partners = [
            ExchangePartner(
                partner_id="partner-fbi",
                name="FBI Cyber Division",
                organization_type=OrganizationType.GOVERNMENT,
                country="US",
                verified=True,
                trust_score=0.95,
                data_classification="CONFIDENTIAL"
            ),
            ExchangePartner(
                partner_id="partner-europol",
                name="Europol EC3",
                organization_type=OrganizationType.GOVERNMENT,
                country="EU",
                verified=True,
                trust_score=0.93,
                data_classification="CONFIDENTIAL"
            ),
            ExchangePartner(
                partner_id="partner-isac",
                name="Financial Services ISAC",
                organization_type=OrganizationType.ENTERPRISE,
                country="US",
                verified=True,
                trust_score=0.88,
                data_classification="INTERNAL"
            )
        ]
        for partner in sample_partners:
            self.partners[partner.partner_id] = partner
    
    def add_partner(self, partner: ExchangePartner) -> str:
        """Add a partner to the federation"""
        self.partners[partner.partner_id] = partner
        return partner.partner_id
    
    def get_partner(self, partner_id: str) -> Optional[ExchangePartner]:
        """Get a partner by ID"""
        return self.partners.get(partner_id)
    
    def get_partners_by_type(self, org_type: OrganizationType) -> List[ExchangePartner]:
        """Get partners by organization type"""
        return [p for p in self.partners.values() if p.organization_type == org_type]
    
    def get_partners_by_country(self, country: str) -> List[ExchangePartner]:
        """Get partners by country"""
        return [p for p in self.partners.values() if p.country == country]
    
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
    ) -> Optional[SharedIntelligence]:
        """Share intelligence with partners"""
        # Verify sender is a valid partner
        if from_partner not in self.partners:
            return None
        
        # Verify all recipients are valid partners
        for partner_id in to_partners:
            if partner_id not in self.partners:
                return None
        
        # Check governance rules
        if not self._check_governance(classification, from_partner, to_partners):
            return None
        
        share = SharedIntelligence(
            share_id=str(uuid4()),
            title=title,
            description=description,
            intelligence_type=intelligence_type,
            from_partner=from_partner,
            to_partners=to_partners,
            classification=DataClassification(classification),
            status=ShareStatus.APPROVED,
            threat_indicators=threat_indicators,
            expires_at=datetime.utcnow() + timedelta(days=expires_in_days)
        )
        self.shares[share.share_id] = share
        return share
    
    def _check_governance(
        self,
        classification: str,
        from_partner: str,
        to_partners: List[str]
    ) -> bool:
        """Check if sharing complies with governance rules"""
        # For this implementation, allow sharing if partners are verified
        from_p = self.partners.get(from_partner)
        if not from_p or not from_p.verified:
            return False
        
        for partner_id in to_partners:
            partner = self.partners.get(partner_id)
            if not partner or not partner.verified:
                return False
        
        return True
    
    def search_intelligence(
        self,
        query: Optional[str] = None,
        intelligence_type: Optional[str] = None,
        from_partner: Optional[str] = None,
        classification: Optional[str] = None
    ) -> List[SharedIntelligence]:
        """Search shared intelligence"""
        results = list(self.shares.values())
        
        if query:
            query_lower = query.lower()
            results = [
                r for r in results
                if query_lower in r.title.lower() or query_lower in r.description.lower()
            ]
        
        if intelligence_type:
            results = [r for r in results if r.intelligence_type == intelligence_type]
        
        if from_partner:
            results = [r for r in results if r.from_partner == from_partner]
        
        if classification:
            results = [r for r in results if r.classification.value == classification]
        
        # Filter expired shares
        results = [r for r in results if r.status != ShareStatus.EXPIRED]
        
        return sorted(results, key=lambda r: r.created_at, reverse=True)
    
    def get_federation_stats(self) -> Dict[str, Any]:
        """Get federation statistics"""
        by_type: Dict[str, int] = {}
        by_country: Dict[str, int] = {}
        total_shares = len(self.shares)
        
        for partner in self.partners.values():
            by_type[partner.organization_type.value] = by_type.get(partner.organization_type.value, 0) + 1
            by_country[partner.country] = by_country.get(partner.country, 0) + 1
        
        return {
            "total_partners": len(self.partners),
            "total_shares": total_shares,
            "by_organization_type": by_type,
            "by_country": by_country,
            "verified_partners": len([p for p in self.partners.values() if p.verified])
        }