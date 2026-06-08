import os
import ipaddress
import logging
from fastapi import Request

logger = logging.getLogger(__name__)

def _get_trusted_proxy_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse AEGIS_TRUSTED_PROXIES into a list of network objects."""
    trusted_networks = []
    env_proxies = os.getenv("AEGIS_TRUSTED_PROXIES", "")
    if not env_proxies.strip():
        return []
    
    for proxy_str in env_proxies.split(","):
        proxy_str = proxy_str.strip()
        if not proxy_str:
            continue
        try:
            # strict=False allows e.g. 192.168.1.1/24 to be parsed as 192.168.1.0/24
            trusted_networks.append(ipaddress.ip_network(proxy_str, strict=False))
        except ValueError as e:
            logger.warning(f"Invalid trusted proxy configuration '{proxy_str}': {e}")
            
    return trusted_networks

# Cache the parsing at module load to avoid parsing on every request
_TRUSTED_NETWORKS = _get_trusted_proxy_networks()

def is_trusted_proxy(ip_str: str) -> bool:
    """Check if the given IP address string is a trusted proxy."""
    if not _TRUSTED_NETWORKS:
        return False
        
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
        
    return any(ip_obj in network for network in _TRUSTED_NETWORKS)

def get_remote_address(request: Request) -> str:
    """
    Securely determine the client's true IP address by validating X-Forwarded-For.
    
    Traverses the X-Forwarded-For chain from right (closest proxy) to left (original client).
    Only accepts X-Forwarded-For IPs if all previous hops are explicitly trusted proxies.
    
    Returns the immediate client IP (request.client.host) if it is not a trusted proxy,
    or if no trusted proxies are configured.
    """
    client = getattr(request, "client", None)
    direct_ip = getattr(client, "host", "unknown")
    
    # If the direct connection is not from a trusted proxy, we cannot trust X-Forwarded-For at all
    if not is_trusted_proxy(direct_ip):
        return direct_ip
        
    forwarded_for = request.headers.get("X-Forwarded-For")
    if not forwarded_for:
        # Check X-Real-IP as a fallback if the direct connection IS trusted
        real_ip = request.headers.get("X-Real-IP")
        if real_ip and real_ip.strip():
            # Ideally we'd validate if real_ip is valid, but returning it is the standard fallback
            return real_ip.strip()
        return direct_ip
        
    # X-Forwarded-For format is typically: client, proxy1, proxy2
    # The right-most IP is the proxy that connected to our trusted proxy.
    ips = [ip.strip() for ip in forwarded_for.split(",") if ip.strip()]
    
    # We traverse right-to-left
    # Example: IPs = [SpoofedClient, RealClient, UntrustedProxy, TrustedProxy]
    # direct_ip = TrustedProxy2 (which is trusted, so we're here)
    # We check TrustedProxy. Trusted? Yes.
    # We check UntrustedProxy. Trusted? No. So UntrustedProxy is the "real client" from our perspective.
    
    for i in reversed(range(len(ips))):
        current_ip = ips[i]
        # If this hop is NOT a trusted proxy, it must be the real client
        if not is_trusted_proxy(current_ip):
            return current_ip
            
    # If ALL IPs in the X-Forwarded-For chain are trusted proxies, the client is the left-most IP.
    if ips:
        return ips[0]
        
    return direct_ip
