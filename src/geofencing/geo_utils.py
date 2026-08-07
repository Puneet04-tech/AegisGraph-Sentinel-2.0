"""Pure geospatial helpers: distance, bounding boxes, and point containment."""

import math

EARTH_RADIUS_KM = 6371.0088
_BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz"


def haversine(lat1, lon1, lat2, lon2):
    """Great-circle distance in kilometres between two lat/lon points."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(d_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return EARTH_RADIUS_KM * c


def bbox(lat, lon, radius_km):
    """Return ``(min_lat, min_lon, max_lat, max_lon)`` for a circle of *radius_km*."""
    delta_lat = math.degrees(radius_km / EARTH_RADIUS_KM)
    cos_lat = max(abs(math.cos(math.radians(lat))), 1e-9)
    delta_lon = math.degrees(radius_km / (EARTH_RADIUS_KM * cos_lat))
    return (
        max(-90.0, lat - delta_lat),
        lon - delta_lon,
        min(90.0, lat + delta_lat),
        lon + delta_lon,
    )


def _on_segment(px, py, x1, y1, x2, y2):
    cross = (px - x1) * (y2 - y1) - (py - y1) * (x2 - x1)
    if abs(cross) > 1e-12:
        return False
    return min(x1, x2) <= px <= max(x1, x2) and min(y1, y2) <= py <= max(y1, y2)


def point_in_polygon(lat, lon, polygon):
    """Ray-casting test; polygon is a list of ``(lat, lon)``, boundary counts."""
    if not polygon:
        return False
    x, y = lon, lat
    inside = False
    n = len(polygon)
    j = n - 1
    for i in range(n):
        lat_i, lon_i = polygon[i]
        lat_j, lon_j = polygon[j]
        xi, yi = lon_i, lat_i
        xj, yj = lon_j, lat_j
        if _on_segment(x, y, xi, yi, xj, yj):
            return True
        if ((yi > y) != (yj > y)) and (x < (xj - xi) * (y - yi) / (yj - yi) + xi):
            inside = not inside
        j = i
    return inside


def geo_hash(lat, lon, precision=5):
    """Deterministic base32 geohash-like string of exactly *precision* chars."""
    lat_lo, lat_hi = -90.0, 90.0
    lon_lo, lon_hi = -180.0, 180.0
    result = []
    ch, bit, even = 0, 0, True
    while len(result) < precision:
        if even:
            mid = (lon_lo + lon_hi) / 2.0
            if lon >= mid:
                ch = (ch << 1) | 1
                lon_lo = mid
            else:
                ch <<= 1
                lon_hi = mid
        else:
            mid = (lat_lo + lat_hi) / 2.0
            if lat >= mid:
                ch = (ch << 1) | 1
                lat_lo = mid
            else:
                ch <<= 1
                lat_hi = mid
        even = not even
        bit += 1
        if bit == 5:
            result.append(_BASE32[ch])
            ch, bit = 0, 0
    return "".join(result)


def lat_lon_valid(lat, lon):
    """True if *lat* in [-90, 90] and *lon* in [-180, 180] (numeric inputs only)."""
    if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
        return False
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0
