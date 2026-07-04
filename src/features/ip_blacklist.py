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

def is_ip_blacklisted(ip_str: str) -> bool:
    """Check if the given IP address is in the blacklisted subnets."""
    if not ip_str:
        return False
    try:
        # Strip port or whitespace if present
        clean_ip = ip_str.split(":")[0].strip()
        ip_obj = ipaddress.ip_address(clean_ip)
        for subnet in BLACKLISTED_SUBNETS:
            if ip_obj in subnet:
                return True
    except ValueError:
        # Invalid IP address format
        return False
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
