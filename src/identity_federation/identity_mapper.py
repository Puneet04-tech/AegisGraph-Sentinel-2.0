"""
Identity Mapper

Maps identity attributes and roles from IdP to local user attributes.
"""

import uuid
from datetime import datetime
from typing import Optional

from .models import (
    IdentityProvider,
    FederatedUser,
    RoleMapping,
    IdentityMapping,
)
from .store import IdentityFederationStore


class IdentityMapper:
    """
    Maps identity attributes and roles from IdP to local user attributes.
    
    Handles attribute transformation, role mapping, and claim normalization.
    """
    
    def __init__(self, store: IdentityFederationStore):
        self._store = store
    
    def map_identity(
        self,
        provider: IdentityProvider,
        raw_attributes: dict,
    ) -> dict:
        """
        Map raw IdP attributes to local user attributes.
        
        Args:
            provider: Identity Provider
            raw_attributes: Raw attributes from IdP
        
        Returns:
            Mapped attributes dictionary
        """
        mapped = {}
        
        # Get identity mappings for provider
        mappings = self._store.list_identity_mappings(provider.id, enabled_only=True)
        
        if mappings:
            # Use custom mappings
            for mapping in mappings:
                value = self._get_attribute_value(
                    raw_attributes,
                    mapping.source_attribute,
                    mapping.source_namespace,
                )
                
                if value is None and mapping.default_value:
                    value = mapping.default_value
                
                if value is not None:
                    transformed = self._transform_value(
                        value,
                        mapping.transform_type,
                        mapping.transform_function,
                    )
                    mapped[mapping.target_attribute] = transformed
        else:
            # Use default attribute mappings
            attr_map = provider.attribute_mappings or {}
            
            for target_attr, source_attrs in attr_map.items():
                # Handle both string and list of strings
                if isinstance(source_attrs, list):
                    for source_attr in source_attrs:
                        value = raw_attributes.get(source_attr)
                        if value:
                            mapped[target_attr] = value
                            break
                elif isinstance(source_attrs, str):
                    value = raw_attributes.get(source_attrs)
                    if value:
                        mapped[target_attr] = value
        
        return mapped
    
    def _get_attribute_value(
        self,
        attributes: dict,
        source_attribute: str,
        namespace: Optional[str] = None,
    ) -> Optional[str]:
        """Get attribute value from raw attributes."""
        # Direct lookup
        if source_attribute in attributes:
            return attributes[source_attribute]
        
        # Try with namespace prefix
        if namespace:
            namespaced = f"{namespace}/{source_attribute}"
            if namespaced in attributes:
                return attributes[namespaced]
        
        return None
    
    def _transform_value(
        self,
        value: str,
        transform_type: str,
        transform_function: Optional[str] = None,
    ) -> str:
        """Transform attribute value based on transform type."""
        if transform_type == "lowercase":
            return value.lower()
        elif transform_type == "uppercase":
            return value.upper()
        elif transform_type == "titlecase":
            return value.title()
        elif transform_type == "trim":
            return value.strip()
        elif transform_type == "email_domain":
            # Extract domain from email
            if "@" in value:
                return value.split("@")[1]
            return value
        elif transform_type == "extract_username":
            # Extract username from UPN or email
            if "\\" in value:
                return value.split("\\")[1]
            if "@" in value:
                return value.split("@")[0]
            return value
        elif transform_type == "base64_decode":
            import base64
            try:
                return base64.b64decode(value).decode()
            except Exception:
                return value
        elif transform_type == "direct":
            return value
        
        return value
    
    def map_roles(
        self,
        provider: IdentityProvider,
        raw_groups: list[str],
    ) -> list[str]:
        """
        Map IdP groups to local roles.
        
        Args:
            provider: Identity Provider
            raw_groups: Raw group names from IdP
        
        Returns:
            List of mapped local roles
        """
        roles = set()
        
        # Get role mappings for provider
        mappings = self._store.list_role_mappings(provider.id, enabled_only=True)
        
        if mappings:
            # Apply custom mappings
            for group in raw_groups:
                for mapping in mappings:
                    if self._matches_group(mapping.source_group, group):
                        # Check conditions
                        if self._check_conditions(mapping.conditions, raw_groups):
                            roles.add(mapping.target_role)
        else:
            # Default: use groups as roles
            roles.update(raw_groups)
        
        return list(roles)
    
    def _matches_group(self, source_group: str, raw_group: str) -> bool:
        """Check if source group matches raw group."""
        # Exact match
        if source_group == raw_group:
            return True
        
        # Case-insensitive match
        if source_group.lower() == raw_group.lower():
            return True
        
        # Pattern match (simple wildcard)
        if "*" in source_group:
            import fnmatch
            return fnmatch.fnmatch(raw_group, source_group)
        
        return False
    
    def _check_conditions(
        self,
        conditions: dict,
        raw_groups: list[str],
    ) -> bool:
        """Check if mapping conditions are met."""
        if not conditions:
            return True
        
        # Check required groups
        if "require_groups" in conditions:
            required = conditions["require_groups"]
            if isinstance(required, str):
                required = [required]
            if not any(g in raw_groups for g in required):
                return False
        
        # Check excluded groups
        if "exclude_groups" in conditions:
            excluded = conditions["exclude_groups"]
            if isinstance(excluded, str):
                excluded = [excluded]
            if any(g in raw_groups for g in excluded):
                return False
        
        # Check group count
        if "min_groups" in conditions:
            if len(raw_groups) < conditions["min_groups"]:
                return False
        
        return True
    
    def add_identity_mapping(
        self,
        provider_id: str,
        source_attribute: str,
        target_attribute: str,
        source_namespace: Optional[str] = None,
        transform_type: str = "direct",
        transform_function: Optional[str] = None,
        default_value: Optional[str] = None,
        required: bool = False,
    ) -> IdentityMapping:
        """Add an identity mapping."""
        mapping = IdentityMapping(
            id=str(uuid.uuid4()),
            provider_id=provider_id,
            source_attribute=source_attribute,
            source_namespace=source_namespace,
            target_attribute=target_attribute,
            transform_type=transform_type,
            transform_function=transform_function,
            default_value=default_value,
            required=required,
        )
        
        self._store.add_identity_mapping(mapping)
        return mapping
    
    def add_role_mapping(
        self,
        provider_id: str,
        source_group: str,
        target_role: str,
        source_type: str = "group",
        conditions: Optional[dict] = None,
        priority: int = 0,
    ) -> RoleMapping:
        """Add a role mapping."""
        mapping = RoleMapping(
            id=str(uuid.uuid4()),
            provider_id=provider_id,
            source_group=source_group,
            source_type=source_type,
            target_role=target_role,
            conditions=conditions or {},
            priority=priority,
        )
        
        self._store.add_role_mapping(mapping)
        return mapping
    
    def list_identity_mappings(
        self,
        provider_id: Optional[str] = None,
    ) -> list[IdentityMapping]:
        """List identity mappings."""
        return self._store.list_identity_mappings(provider_id)
    
    def list_role_mappings(
        self,
        provider_id: Optional[str] = None,
    ) -> list[RoleMapping]:
        """List role mappings."""
        return self._store.list_role_mappings(provider_id)
    
    def delete_identity_mapping(self, mapping_id: str) -> bool:
        """Delete an identity mapping."""
        return self._store.delete_identity_mapping(mapping_id)
    
    def delete_role_mapping(self, mapping_id: str) -> bool:
        """Delete a role mapping."""
        return self._store.delete_role_mapping(mapping_id)
    
    def sync_user_roles(
        self,
        user: FederatedUser,
        provider: IdentityProvider,
    ) -> FederatedUser:
        """
        Synchronize user roles from IdP groups.
        
        Args:
            user: Federated user
            provider: Identity Provider
        
        Returns:
            Updated user with synchronized roles
        """
        # Get current groups from profile data
        raw_groups = user.profile_data.get("groups", user.groups)
        
        if isinstance(raw_groups, str):
            raw_groups = [raw_groups]
        
        # Map groups to roles
        user.roles = self.map_roles(provider, raw_groups)
        
        # Update user
        user.updated_at = datetime.utcnow()
        self._store.update_user(user)
        
        return user