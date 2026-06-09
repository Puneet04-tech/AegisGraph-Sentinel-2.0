"""
Multi-Tenant SaaS Platform Models
AegisGraph Sentinel Enterprise
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, JSON, Text, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class SubscriptionTier(str, Enum):
    """Subscription tier levels"""
    COMMUNITY = "community"  # Free tier for individuals/researchers
    PROFESSIONAL = "professional"  # Paid tier for small teams
    ENTERPRISE = "enterprise"  # Full enterprise capabilities


class SubscriptionStatus(str, Enum):
    """Subscription status"""
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    TRIAL = "trial"
    SUSPENDED = "suspended"


class Organization(Base):
    """Organization/Tenant model for multi-tenancy"""
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True)  # UUID
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Billing information
    billing_email = Column(String(255), nullable=True)
    billing_address = Column(JSON, nullable=True)
    
    # Settings
    settings = Column(JSON, default=dict)
    preferences = Column(JSON, default=dict)
    
    # Limits based on subscription
    max_users = Column(Integer, default=5)
    max_api_calls_per_month = Column(Integer, default=10000)
    max_storage_gb = Column(Integer, default=10)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    trial_ends_at = Column(DateTime, nullable=True)
    
    # Relationships
    subscription = relationship("Subscription", back_populates="organization", uselist=False)
    users = relationship("User", back_populates="organization")
    workspaces = relationship("Workspace", back_populates="organization")
    api_keys = relationship("APIKey", back_populates="organization")


class Subscription(Base):
    """Subscription model for billing"""
    __tablename__ = "subscriptions"

    id = Column(String(36), primary_key=True)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    
    tier = Column(SQLEnum(SubscriptionTier), nullable=False)
    status = Column(SQLEnum(SubscriptionStatus), default=SubscriptionStatus.TRIAL)
    
    # Billing cycle
    billing_cycle = Column(String(20), default="monthly")  # monthly, annual
    current_period_start = Column(DateTime, nullable=False)
    current_period_end = Column(DateTime, nullable=False)
    
    # Usage tracking
    api_calls_this_period = Column(Integer, default=0)
    storage_used_gb = Column(Integer, default=0)
    
    # Stripe integration
    stripe_subscription_id = Column(String(255), nullable=True, index=True)
    stripe_customer_id = Column(String(255), nullable=True, index=True)
    
    # Cancellation
    canceled_at = Column(DateTime, nullable=True)
    cancellation_reason = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="subscription")
    invoices = relationship("Invoice", back_populates="subscription")


class User(Base):
    """User model with organization membership"""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    email_verified = Column(Boolean, default=False)
    
    # Identity
    username = Column(String(100), unique=True, nullable=True, index=True)
    full_name = Column(String(255), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    phone = Column(String(50), nullable=True)
    
    # Authentication
    password_hash = Column(String(255), nullable=True)  # For local auth
    password_changed_at = Column(DateTime, nullable=True)
    
    # MFA
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)
    mfa_backup_codes = Column(JSON, nullable=True)
    
    # SSO
    sso_provider = Column(String(50), nullable=True)
    sso_provider_id = Column(String(255), nullable=True)
    
    # Organization membership
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    role = Column(String(50), default="member")  # owner, admin, member, viewer
    is_org_owner = Column(Boolean, default=False)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_superadmin = Column(Boolean, default=False)  # AegisGraph internal admin
    
    # Preferences
    preferences = Column(JSON, default=dict)
    
    # Last activity
    last_login_at = Column(DateTime, nullable=True)
    last_activity_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="users")
    sessions = relationship("UserSession", back_populates="user")


class UserSession(Base):
    """User session model for tracking active sessions"""
    __tablename__ = "user_sessions"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    
    # Session info
    token = Column(String(500), unique=True, nullable=False, index=True)
    refresh_token = Column(String(500), unique=True, nullable=True, index=True)
    
    # Client info
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)
    device_id = Column(String(255), nullable=True)
    
    # Location
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Expiration
    expires_at = Column(DateTime, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="sessions")


class Workspace(Base):
    """Workspace model for team separation within organization"""
    __tablename__ = "workspaces"

    id = Column(String(36), primary_key=True)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    
    name = Column(String(255), nullable=False)
    slug = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    
    # Configuration
    settings = Column(JSON, default=dict)
    
    # Limits
    max_members = Column(Integer, default=20)
    max_cases = Column(Integer, default=1000)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="workspaces")
    members = relationship("WorkspaceMember", back_populates="workspace")


class WorkspaceMember(Base):
    """Workspace membership"""
    __tablename__ = "workspace_members"

    id = Column(String(36), primary_key=True)
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    
    role = Column(String(50), default="member")  # admin, member, viewer
    permissions = Column(JSON, default=list)  # Granular permissions
    
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="members")
    user = Column(String(36), ForeignKey("users.id"))  # Simplified relationship


class APIKey(Base):
    """API Key model for programmatic access"""
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Key hash (never store raw key)
    key_hash = Column(String(255), unique=True, nullable=False, index=True)
    key_prefix = Column(String(10), nullable=False)  # First few chars for identification
    
    # Scopes
    scopes = Column(JSON, default=list)  # List of allowed scopes
    
    # Rate limiting
    rate_limit_per_minute = Column(Integer, default=60)
    
    # Status
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    use_count = Column(Integer, default=0)
    
    # User who created
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="api_keys")


class Invoice(Base):
    """Invoice model for billing"""
    __tablename__ = "invoices"

    id = Column(String(36), primary_key=True)
    subscription_id = Column(String(36), ForeignKey("subscriptions.id"), nullable=False)
    
    # Invoice details
    number = Column(String(50), unique=True, nullable=False)
    status = Column(String(20), default="pending")  # pending, paid, overdue, void
    
    # Amounts
    subtotal = Column(Integer, nullable=False)  # In cents
    tax = Column(Integer, default=0)
    total = Column(Integer, nullable=False)
    currency = Column(String(3), default="USD")
    
    # Period
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    
    # Stripe
    stripe_invoice_id = Column(String(255), nullable=True, index=True)
    stripe_payment_intent_id = Column(String(255), nullable=True)
    
    # PDF
    pdf_url = Column(String(500), nullable=True)
    
    # Paid info
    paid_at = Column(DateTime, nullable=True)
    payment_method = Column(String(50), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    subscription = relationship("Subscription", back_populates="invoices")


# Pydantic models for API
class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)
    billing_email: Optional[str] = None
    description: Optional[str] = None


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    billing_email: Optional[str] = None
    description: Optional[str] = None
    settings: Optional[dict] = None


class UserCreate(BaseModel):
    email: EmailStr
    username: Optional[str] = Field(None, max_length=100)
    full_name: Optional[str] = Field(None, max_length=255)
    password: Optional[str] = Field(None, min_length=8)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, max_length=100)
    full_name: Optional[str] = Field(None, max_length=255)
    avatar_url: Optional[str] = None
    phone: Optional[str] = None
    preferences: Optional[dict] = None


class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None


class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    rate_limit_per_minute: int = Field(default=60, ge=1, le=1000)
    expires_at: Optional[datetime] = None


class SubscriptionUpdate(BaseModel):
    tier: Optional[SubscriptionTier] = None
    billing_cycle: Optional[str] = None


# Response models
class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str]
    is_active: bool
    is_verified: bool
    subscription_tier: Optional[SubscriptionTier]
    created_at: datetime

    class Config:
        from_attributes = True


class UserResponse(BaseModel):
    id: str
    email: str
    username: Optional[str]
    full_name: Optional[str]
    avatar_url: Optional[str]
    organization_id: str
    role: str
    is_active: bool
    mfa_enabled: bool
    last_login_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class WorkspaceResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str]
    organization_id: str
    is_active: bool
    is_default: bool
    created_at: datetime

    class Config:
        from_attributes = True


class APIKeyResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    key_prefix: str
    scopes: List[str]
    rate_limit_per_minute: int
    is_active: bool
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    use_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class UsageResponse(BaseModel):
    api_calls_this_period: int
    max_api_calls: int
    storage_used_gb: float
    max_storage_gb: int
    period_start: datetime
    period_end: datetime
    usage_percentage: float