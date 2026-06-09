"""
Enterprise Billing & Licensing Service
AegisGraph Sentinel Enterprise
Integrates with Stripe for subscriptions, usage metering, and license management
"""

import stripe
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum

from src.exceptions import BillingError


class PriceTier(str, Enum):
    """Pricing tiers"""
    COMMUNITY = "community"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


@dataclass
class PlanDetails:
    """Subscription plan details"""
    tier: PriceTier
    name: str
    description: str
    price_monthly: int  # In cents
    price_annual: int  # In cents
    features: List[str]
    limits: Dict[str, int]


# Plan configurations
PLANS = {
    PriceTier.COMMUNITY: PlanDetails(
        tier=PriceTier.COMMUNITY,
        name="Community Edition",
        description="Free tier for individuals and researchers",
        price_monthly=0,
        price_annual=0,
        features=[
            "Real-time fraud detection",
            "Basic graph analytics",
            "Up to 10,000 API calls/month",
            "5 team members",
            "10GB storage",
            "Community support",
            "Basic reporting",
        ],
        limits={
            "api_calls_per_month": 10000,
            "max_users": 5,
            "storage_gb": 10,
            "cases_per_month": 100,
            "api_keys": 2,
        },
    ),
    PriceTier.PROFESSIONAL: PlanDetails(
        tier=PriceTier.PROFESSIONAL,
        name="Professional Edition",
        description="For growing teams and businesses",
        price_monthly=49900,  # $499/month
        price_annual=47900 * 12,  # $47,900/year (20% discount)
        features=[
            "Everything in Community",
            "Advanced ML models (HTGNN Pro)",
            "Unlimited API calls",
            "25 team members",
            "100GB storage",
            "Email support",
            "Custom dashboards",
            "API access with higher rate limits",
            "SSO integration (Google, Microsoft)",
            "Basic audit logging",
        ],
        limits={
            "api_calls_per_month": -1,  # Unlimited
            "max_users": 25,
            "storage_gb": 100,
            "cases_per_month": 1000,
            "api_keys": 10,
        },
    ),
    PriceTier.ENTERPRISE: PlanDetails(
        tier=PriceTier.ENTERPRISE,
        name="Enterprise Edition",
        description="Full enterprise capabilities",
        price_monthly=199900,  # $1,999/month
        price_annual=179900 * 12,  # $1,799/month (10% discount)
        features=[
            "Everything in Professional",
            "Custom HTGNN model training",
            "AI Agent platform (Investigation, Threat, Compliance)",
            "Unlimited team members",
            "Unlimited storage",
            "Priority support with SLA",
            "Advanced analytics & BI integration",
            "All SSO providers (Okta, Azure AD, SAML)",
            "Full audit logging & compliance",
            "Custom integrations (Splunk, ServiceNow, etc.)",
            "Dedicated account manager",
            "SOC2 Type II compliance",
        ],
        limits={
            "api_calls_per_month": -1,  # Unlimited
            "max_users": -1,  # Unlimited
            "storage_gb": -1,  # Unlimited
            "cases_per_month": -1,  # Unlimited
            "api_keys": -1,  # Unlimited
        },
    ),
}


class BillingService:
    """Enterprise billing service with Stripe integration"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        stripe.api_key = config.get("stripe_api_key", "sk_test_...")
        
        self.webhook_secret = config.get("stripe_webhook_secret")
        self.currency = config.get("currency", "usd")
        
        # Price IDs from Stripe dashboard
        self.price_ids = {
            PriceTier.COMMUNITY: config.get("stripe_price_community"),
            PriceTier.PROFESSIONAL_MONTHLY: config.get("stripe_price_professional_monthly"),
            PriceTier.PROFESSIONAL_ANNUAL: config.get("stripe_price_professional_annual"),
            PriceTier.ENTERPRISE_MONTHLY: config.get("stripe_price_enterprise_monthly"),
            PriceTier.ENTERPRISE_ANNUAL: config.get("stripe_price_enterprise_annual"),
        }

    def create_customer(
        self,
        email: str,
        name: str,
        organization_id: str,
        metadata: Optional[Dict[str, str]] = None,
    ) -> str:
        """Create Stripe customer"""
        try:
            customer = stripe.Customer.create(
                email=email,
                name=name,
                metadata={
                    "organization_id": organization_id,
                    **(metadata or {}),
                },
            )
            return customer.id
        except stripe.error.StripeError as e:
            raise BillingError(f"Failed to create customer: {e}")

    def create_subscription(
        self,
        customer_id: str,
        tier: PriceTier,
        billing_cycle: str = "monthly",
        trial_days: int = 14,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Create subscription for customer"""
        try:
            # Get price ID based on tier and billing cycle
            if tier == PriceTier.COMMUNITY:
                price_id = None
            elif tier == PriceTier.PROFESSIONAL:
                price_id = self.price_ids.get(
                    PriceTier.PROFESSIONAL_ANNUAL if billing_cycle == "annual" 
                    else PriceTier.PROFESSIONAL_MONTHLY
                )
            else:  # Enterprise
                price_id = self.price_ids.get(
                    PriceTier.ENTERPRISE_ANNUAL if billing_cycle == "annual"
                    else PriceTier.ENTERPRISE_MONTHLY
                )

            subscription_params = {
                "customer": customer_id,
                "metadata": {
                    "tier": tier.value,
                    "billing_cycle": billing_cycle,
                    **(metadata or {}),
                },
            }

            if price_id:
                subscription_params["items"] = [{"price": price_id}]

            if trial_days > 0 and tier != PriceTier.COMMUNITY:
                subscription_params["trial_period_days"] = trial_days

            subscription = stripe.Subscription.create(**subscription_params)
            
            return {
                "subscription_id": subscription.id,
                "status": subscription.status,
                "current_period_start": datetime.fromtimestamp(subscription.current_period_start),
                "current_period_end": datetime.fromtimestamp(subscription.current_period_end),
                "trial_end": datetime.fromtimestamp(subscription.trial_end) if subscription.trial_end else None,
            }
        except stripe.error.StripeError as e:
            raise BillingError(f"Failed to create subscription: {e}")

    def get_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Get subscription details"""
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            return {
                "id": subscription.id,
                "status": subscription.status,
                "tier": subscription.metadata.get("tier"),
                "current_period_start": datetime.fromtimestamp(subscription.current_period_start),
                "current_period_end": datetime.fromtimestamp(subscription.current_period_end),
                "cancel_at_period_end": subscription.cancel_at_period_end,
            }
        except stripe.error.StripeError as e:
            raise BillingError(f"Failed to get subscription: {e}")

    def update_subscription(
        self,
        subscription_id: str,
        new_tier: Optional[PriceTier] = None,
        billing_cycle: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update subscription (upgrade/downgrade)"""
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            
            if new_tier:
                # Get new price ID
                if new_tier == PriceTier.PROFESSIONAL:
                    price_id = self.price_ids.get(
                        PriceTier.PROFESSIONAL_ANNUAL if billing_cycle == "annual"
                        else PriceTier.PROFESSIONAL_MONTHLY
                    )
                else:
                    price_id = self.price_ids.get(
                        PriceTier.ENTERPRISE_ANNUAL if billing_cycle == "annual"
                        else PriceTier.ENTERPRISE_MONTHLY
                    )
                
                # Prorate based on usage
                subscription = stripe.Subscription.modify(
                    subscription_id,
                    items=[{
                        "id": subscription.items.data[0].id,
                        "price": price_id,
                    }],
                    proration_behavior="create_prorations",
                    metadata={
                        "tier": new_tier.value,
                        "billing_cycle": billing_cycle or subscription.metadata.get("billing_cycle", "monthly"),
                    },
                )
            
            return {
                "subscription_id": subscription.id,
                "status": subscription.status,
                "updated": True,
            }
        except stripe.error.StripeError as e:
            raise BillingError(f"Failed to update subscription: {e}")

    def cancel_subscription(
        self,
        subscription_id: str,
        cancel_at_period_end: bool = True,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel subscription"""
        try:
            if cancel_at_period_end:
                subscription = stripe.Subscription.modify(
                    subscription_id,
                    cancel_at_period_end=True,
                    metadata={"cancellation_reason": reason or ""},
                )
            else:
                subscription = stripe.Subscription.delete(subscription_id)
            
            return {
                "subscription_id": subscription.id,
                "status": subscription.status,
                "canceled": True,
                "effective_date": datetime.fromtimestamp(subscription.current_period_end) if cancel_at_period_end else datetime.utcnow(),
            }
        except stripe.error.StripeError as e:
            raise BillingError(f"Failed to cancel subscription: {e}")

    def create_checkout_session(
        self,
        customer_id: str,
        tier: PriceTier,
        success_url: str,
        cancel_url: str,
        billing_cycle: str = "monthly",
    ) -> str:
        """Create Stripe Checkout session"""
        try:
            plan = PLANS[tier]
            
            if tier == PriceTier.COMMUNITY:
                return None  # No checkout needed for free tier
            
            price_id = self.price_ids.get(
                PriceTier.PROFESSIONAL_ANNUAL if tier == PriceTier.PROFESSIONAL and billing_cycle == "annual"
                else PriceTier.PROFESSIONAL_MONTHLY if tier == PriceTier.PROFESSIONAL
                else PriceTier.ENTERPRISE_ANNUAL if tier == PriceTier.ENTERPRISE and billing_cycle == "annual"
                else PriceTier.ENTERPRISE_MONTHLY
            )
            
            session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=["card"],
                line_items=[{
                    "price": price_id,
                    "quantity": 1,
                }],
                mode="subscription",
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={
                    "tier": tier.value,
                    "billing_cycle": billing_cycle,
                },
            )
            
            return session.url
        except stripe.error.StripeError as e:
            raise BillingError(f"Failed to create checkout session: {e}")

    def create_invoice(
        self,
        customer_id: str,
        amount: int,
        description: str,
        currency: str = "usd",
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Create and finalize invoice"""
        try:
            invoice = stripe.Invoice.create(
                customer=customer_id,
                auto_advance=True,
                collection_method="send_invoice",
                days_until_due=30,
                metadata=metadata or {},
            )
            
            stripe.InvoiceItem.create(
                customer=customer_id,
                invoice=invoice.id,
                amount=amount,
                currency=currency,
                description=description,
            )
            
            finalized_invoice = stripe.Invoice.finalize_invoice(invoice.id)
            
            return {
                "invoice_id": finalized_invoice.id,
                "number": finalized_invoice.number,
                "status": finalized_invoice.status,
                "amount_due": finalized_invoice.amount_due,
                "hosted_invoice_url": finalized_invoice.hosted_invoice_url,
                "pdf_url": finalized_invoice.invoice_pdf,
            }
        except stripe.error.StripeError as e:
            raise BillingError(f"Failed to create invoice: {e}")

    def get_invoices(self, customer_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get list of invoices for customer"""
        try:
            invoices = stripe.Invoice.list(customer=customer_id, limit=limit)
            return [
                {
                    "id": inv.id,
                    "number": inv.number,
                    "status": inv.status,
                    "amount_due": inv.amount_due,
                    "currency": inv.currency,
                    "created": datetime.fromtimestamp(inv.created),
                    "pdf_url": inv.invoice_pdf,
                    "hosted_invoice_url": inv.hosted_invoice_url,
                }
                for inv in invoices.data
            ]
        except stripe.error.StripeError as e:
            raise BillingError(f"Failed to get invoices: {e}")

    def get_usage(
        self,
        subscription_id: str,
        period_start: datetime,
        period_end: datetime,
    ) -> Dict[str, Any]:
        """Get usage metrics for billing period"""
        try:
            # Get usage from Stripe
            usage_records = stripe.UsageRecord.list(
                subscription_item=self._get_subscription_item(subscription_id),
                limit=100,
            )
            
            total_usage = sum(record.amount for record in usage_records.data)
            
            return {
                "period_start": period_start,
                "period_end": period_end,
                "total_api_calls": total_usage,
            }
        except stripe.error.StripeError as e:
            raise BillingError(f"Failed to get usage: {e}")

    def record_usage(
        self,
        subscription_item_id: str,
        quantity: int,
        timestamp: datetime,
    ) -> Dict[str, Any]:
        """Record usage for metered billing"""
        try:
            record = stripe.UsageRecord.create(
                subscription_item=subscription_item_id,
                quantity=quantity,
                timestamp=int(timestamp.timestamp()),
            )
            return {
                "id": record.id,
                "quantity": record.quantity,
                "action": record.action,
            }
        except stripe.error.StripeError as e:
            raise BillingError(f"Failed to record usage: {e}")

    def handle_webhook(
        self,
        payload: bytes,
        signature: str,
    ) -> Dict[str, Any]:
        """Handle Stripe webhook events"""
        try:
            event = stripe.Webhook.construct_event(
                payload, signature, self.webhook_secret
            )
            
            event_type = event["type"]
            data = event["data"]["object"]
            
            if event_type == "customer.subscription.created":
                return self._handle_subscription_created(data)
            elif event_type == "customer.subscription.updated":
                return self._handle_subscription_updated(data)
            elif event_type == "customer.subscription.deleted":
                return self._handle_subscription_deleted(data)
            elif event_type == "invoice.payment_succeeded":
                return self._handle_invoice_paid(data)
            elif event_type == "invoice.payment_failed":
                return self._handle_invoice_failed(data)
            elif event_type == "customer.subscription.trial_will_end":
                return self._handle_trial_ending(data)
            
            return {"handled": True, "event_type": event_type}
            
        except stripe.error.SignatureVerificationError:
            raise BillingError("Invalid webhook signature")
        except stripe.error.StripeError as e:
            raise BillingError(f"Webhook error: {e}")

    def _handle_subscription_created(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription created event"""
        return {
            "event": "subscription_created",
            "subscription_id": data["id"],
            "customer_id": data["customer"],
            "status": data["status"],
            "tier": data["metadata"].get("tier"),
        }

    def _handle_subscription_updated(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription updated event"""
        return {
            "event": "subscription_updated",
            "subscription_id": data["id"],
            "status": data["status"],
        }

    def _handle_subscription_deleted(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription deleted event"""
        return {
            "event": "subscription_deleted",
            "subscription_id": data["id"],
        }

    def _handle_invoice_paid(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice paid event"""
        return {
            "event": "invoice_paid",
            "invoice_id": data["id"],
            "amount_paid": data["amount_paid"],
            "period_start": datetime.fromtimestamp(data["period_start"]),
            "period_end": datetime.fromtimestamp(data["period_end"]),
        }

    def _handle_invoice_failed(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice payment failed event"""
        return {
            "event": "invoice_failed",
            "invoice_id": data["id"],
            "amount_due": data["amount_due"],
            "next_payment_attempt": datetime.fromtimestamp(data["next_payment_attempt"]) if data.get("next_payment_attempt") else None,
        }

    def _handle_trial_ending(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle trial ending event"""
        return {
            "event": "trial_ending",
            "subscription_id": data["id"],
            "trial_end": datetime.fromtimestamp(data["trial_end"]),
        }

    def _get_subscription_item(self, subscription_id: str) -> str:
        """Get subscription item ID for usage recording"""
        subscription = stripe.Subscription.retrieve(subscription_id)
        return subscription.items.data[0].id


class UsageMeteringService:
    """Usage metering for subscription limits"""

    def __init__(self, billing_service: BillingService):
        self.billing_service = billing_service

    def check_limit(
        self,
        organization_id: str,
        limit_type: str,
        current_usage: int,
        plan: PriceTier,
    ) -> Dict[str, Any]:
        """Check if usage is within limits"""
        plan_details = PLANS[plan]
        limits = plan_details.limits
        
        limit = limits.get(limit_type, 0)
        
        if limit == -1:  # Unlimited
            return {
                "within_limit": True,
                "current_usage": current_usage,
                "limit": None,
                "percentage": 0,
            }
        
        percentage = (current_usage / limit) * 100 if limit > 0 else 0
        
        return {
            "within_limit": current_usage < limit,
            "current_usage": current_usage,
            "limit": limit,
            "remaining": max(0, limit - current_usage),
            "percentage": percentage,
            "approaching_limit": percentage >= 80,
            "over_limit": current_usage >= limit,
        }

    def enforce_rate_limit(
        self,
        api_key: str,
        requests_per_minute: int,
        limit: int,
    ) -> Dict[str, Any]:
        """Enforce API rate limiting"""
        # In production, use Redis for rate limiting
        # Implementation would use sliding window algorithm
        
        return {
            "allowed": requests_per_minute < limit,
            "remaining": max(0, limit - requests_per_minute),
            "reset_at": datetime.utcnow() + timedelta(minutes=1),
        }


# Initialize billing service
billing_service = BillingService({
    "stripe_api_key": "sk_test_...",
    "stripe_webhook_secret": "whsec_...",
    "currency": "usd",
})