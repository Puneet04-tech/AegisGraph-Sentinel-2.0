"""Unit tests for src.geofencing.geo_utils."""

import math

import pytest

from src.geofencing.geo_utils import (
    bbox,
    geo_hash,
    haversine,
    lat_lon_valid,
    point_in_polygon,
)

PARIS = (48.8566, 2.3522)
LONDON = (51.5074, -0.1278)


class TestHaversine:
    def test_paris_to_london_distance(self):
        dist = haversine(*PARIS, *LONDON)
        assert dist == pytest.approx(343.5, abs=5.0)

    def test_identical_points_zero(self):
        assert haversine(0.0, 0.0, 0.0, 0.0) == 0.0

    def test_antipodal_distance(self):
        dist = haversine(0.0, 0.0, 0.0, 180.0)
        assert dist == pytest.approx(math.pi * 6371.0088, abs=5.0)

    def test_north_to_south_pole(self):
        dist = haversine(90.0, 0.0, -90.0, 0.0)
        assert dist == pytest.approx(math.pi * 6371.0088, rel=1e-6)

    def test_symmetric(self):
        assert haversine(52.0, 13.0, 48.0, 2.0) == pytest.approx(
            haversine(48.0, 2.0, 52.0, 13.0)
        )


class TestBBox:
    def test_center_inside_bbox(self):
        min_lat, min_lon, max_lat, max_lon = bbox(10.0, 20.0, 100.0)
        assert min_lat < 10.0 < max_lat
        assert min_lon < 20.0 < max_lon

    def test_corners_radius_correct(self):
        min_lat, min_lon, max_lat, max_lon = bbox(0.0, 0.0, 111.195)
        assert min_lat == pytest.approx(-1.0, abs=1e-3)
        assert max_lat == pytest.approx(1.0, abs=1e-3)
        assert min_lon == pytest.approx(-1.0, abs=1e-3)
        assert max_lon == pytest.approx(1.0, abs=1e-3)

    def test_zero_radius_point_bbox(self):
        assert bbox(5.0, 5.0, 0.0) == (5.0, 5.0, 5.0, 5.0)

    def test_larger_radius_wider_box(self):
        small = bbox(0.0, 0.0, 10.0)
        large = bbox(0.0, 0.0, 50.0)
        assert large[0] < small[0]
        assert large[2] > small[2]
        assert large[1] < small[1]
        assert large[3] > small[3]

    def test_returns_tuple_of_four(self):
        result = bbox(1.0, 1.0, 1.0)
        assert isinstance(result, tuple)
        assert len(result) == 4


class TestPointInPolygon:
    SQUARE = [(0.0, 0.0), (0.0, 10.0), (10.0, 10.0), (10.0, 0.0)]
    CONCAVE = [(0.0, 0.0), (0.0, 10.0), (10.0, 10.0), (5.0, 5.0), (10.0, 0.0)]

    def test_inside(self):
        assert point_in_polygon(5.0, 5.0, self.SQUARE) is True

    def test_outside(self):
        assert point_in_polygon(15.0, 5.0, self.SQUARE) is False

    def test_on_edge(self):
        assert point_in_polygon(0.0, 5.0, self.SQUARE) is True

    def test_on_vertex(self):
        assert point_in_polygon(10.0, 10.0, self.SQUARE) is True

    def test_concave_notch_outside(self):
        assert point_in_polygon(8.0, 5.0, self.CONCAVE) is False

    def test_concave_solid_region_inside(self):
        assert point_in_polygon(3.0, 8.0, self.CONCAVE) is True

    def test_empty_polygon(self):
        assert point_in_polygon(0.0, 0.0, []) is False

    def test_open_equivalent_to_closed(self):
        closed = self.SQUARE + [(0.0, 0.0)]
        assert point_in_polygon(5.0, 5.0, closed) is point_in_polygon(
            5.0, 5.0, self.SQUARE
        )


class TestGeoHash:
    def test_deterministic(self):
        assert geo_hash(*PARIS) == geo_hash(*PARIS)

    def test_length_equals_precision(self):
        for precision in range(1, 8):
            assert len(geo_hash(*PARIS, precision)) == precision

    def test_default_precision_is_five(self):
        assert len(geo_hash(*PARIS)) == 5

    def test_nearby_points_share_prefix(self):
        a = geo_hash(48.8566, 2.3522, 8)
        b = geo_hash(48.8567, 2.3523, 8)
        assert a[:4] == b[:4]

    def test_far_points_differ(self):
        assert geo_hash(*PARIS) != geo_hash(-33.8688, 151.2093)

    def test_only_base32_chars(self):
        allowed = set("0123456789bcdefghjkmnpqrstuvwxyz")
        assert set(geo_hash(20.0, -30.0, 12)) <= allowed


class TestLatLonValid:
    def test_valid_bounds(self):
        assert lat_lon_valid(90.0, 180.0) is True
        assert lat_lon_valid(-90.0, -180.0) is True
        assert lat_lon_valid(0.0, 0.0) is True

    def test_latitude_out_of_range(self):
        assert lat_lon_valid(90.5, 0.0) is False
        assert lat_lon_valid(-91.0, 0.0) is False

    def test_longitude_out_of_range(self):
        assert lat_lon_valid(0.0, 180.5) is False
        assert lat_lon_valid(0.0, -181.0) is False

    def test_string_inputs_rejected(self):
        assert lat_lon_valid("0.0", "0.0") is False
        assert lat_lon_valid(0.0, "0.0") is False
        assert lat_lon_valid("0.0", 0.0) is False

    def test_none_input_rejected(self):
        assert lat_lon_valid(None, None) is False
