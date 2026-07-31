import ipaddress
import re
from typing import List, Set

# Default blacklisted subnets (can be customized or loaded from settings)
BLACKLISTED_SUBNETS = {
    ipaddress.ip_network("198.51.100.0/22"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
}

# Default blacklisted countries or regions
BLACKLISTED_COUNTRIES = {
    "NORTH KOREA", "KP", "DPRK",
    "IRAN", "IR",
    "SYRIA", "SY",
    "SUDAN", "SD"
}

def _parse_ip(ip_str: str):
    """Parse an IP string into an ipaddress object.

    Handles bare IPv4/IPv6 addresses as well as addresses carrying a port:
    - ``192.0.2.5``
    - ``192.0.2.5:8080``
    - ``2001:db8::1``
    - ``[2001:db8::1]:8080``

    Returns None when the string is not a valid IP address.
    """
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    if not ip_str:
        return None
    # Bracketed IPv6 with optional port: [2001:db8::1] or [2001:db8::1]:8080
    if ip_str.startswith("["):
        close = ip_str.find("]")
        if close == -1:
            return None
        try:
            return ipaddress.ip_address(ip_str[1:close])
        except ValueError:
            return None
    # Bare address first: covers IPv4 and full IPv6 addresses
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        pass
    # IPv4 with a port suffix: exactly one colon separates host and port
    if ip_str.count(":") == 1:
        host, _, _ = ip_str.rpartition(":")
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None
    return None


def is_ip_blacklisted(ip_str: str) -> bool:
    """Check if the given IP address is in the blacklisted subnets."""
    ip_obj = _parse_ip(ip_str)
    if ip_obj is None:
        # Invalid IP address format
        return False
    for subnet in BLACKLISTED_SUBNETS:
        if ip_obj in subnet:
            return True
    return False

def is_location_blacklisted(location_str: str) -> bool:
    """Check if the transaction location contains blacklisted countries/codes."""
    if not location_str:
        return False
    
    upper_loc = location_str.upper()
    for country in BLACKLISTED_COUNTRIES:
        # Use regex to match exact word boundary to prevent partial matches like "IR" in "IRELAND"
        pattern = r'\b' + re.escape(country) + r'\b'
        if re.search(pattern, upper_loc):
            return True
    return False

def check_blacklist(ip_address: str = None, location: str = None) -> bool:
    """Return True if either the IP address or location is blacklisted."""
    if ip_address and is_ip_blacklisted(ip_address):
        return True
    if location and is_location_blacklisted(location):
        return True
    return False
