from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.config.loaders import load_settings
from src.utils import redis_client
from src.utils.cache import RedisGraphCache


def _make_database_settings(**overrides):
    base = {
        "redis_url": "redis://localhost:6379/0",
        "redis_max_connections": 50,
        "redis_socket_timeout": None,
        "redis_socket_connect_timeout": None,
        "redis_retry_on_timeout": False,
        "redis_health_check_interval": None,
        "redis_socket_keepalive": False,
        "neo4j_enabled": True,
        "neo4j_uri": "bolt://localhost:7687",
        "neo4j_user": "neo4j",
        "neo4j_password": "password",
        "neo4j_max_connection_pool_size": 50,
        "neo4j_connection_timeout": None,
        "neo4j_connection_acquisition_timeout": None,
        "neo4j_max_connection_lifetime": 3600.0,
        "neo4j_max_transaction_retry_time": None,
        "neo4j_keep_alive": True,
        "neo4j_liveness_check_timeout": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_load_settings_exposes_database_defaults(tmp_path):
    settings = load_settings(
        config_path=tmp_path / "missing-config.yaml",
        thresholds_path=tmp_path / "missing-thresholds.yaml",
        environ={"AEGIS_ENV": "test"},
    )

    assert settings.database.redis_max_connections == 50
    assert settings.database.neo4j_max_connection_pool_size == 50
    assert settings.database.neo4j_keep_alive is True


def test_load_settings_applies_database_overrides(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
database:
  redis:
    url: redis://yaml.example/0
    max_connections: 11
    socket_timeout: 2.5
    retry_on_timeout: true
  neo4j:
    enabled: true
    uri: bolt://yaml-neo4j:7687
    user: yaml_user
    password: yaml_pass
    max_connection_pool_size: 17
    connection_acquisition_timeout: 7.5
""",
        encoding="utf-8",
    )

    settings = load_settings(
        config_path=config_path,
        thresholds_path=tmp_path / "missing-thresholds.yaml",
        environ={"AEGIS_ENV": "test"},
    )

    assert settings.database.redis_url == "redis://yaml.example/0"
    assert settings.database.redis_max_connections == 11
    assert settings.database.redis_socket_timeout == 2.5
    assert settings.database.redis_retry_on_timeout is True
    assert settings.database.neo4j_enabled is True
    assert settings.database.neo4j_uri == "bolt://yaml-neo4j:7687"
    assert settings.database.neo4j_max_connection_pool_size == 17
    assert settings.database.neo4j_connection_acquisition_timeout == 7.5


def test_database_env_overrides_yaml(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
database:
  redis:
    max_connections: 4
  neo4j:
    max_connection_pool_size: 4
""",
        encoding="utf-8",
    )

    settings = load_settings(
        config_path=config_path,
        thresholds_path=tmp_path / "missing-thresholds.yaml",
        environ={
            "AEGIS_ENV": "test",
            "REDIS_MAX_CONNECTIONS": "13",
            "REDIS_SOCKET_TIMEOUT": "1.25",
            "NEO4J_MAX_CONNECTION_POOL_SIZE": "21",
            "NEO4J_KEEP_ALIVE": "false",
        },
    )

    assert settings.database.redis_max_connections == 13
    assert settings.database.redis_socket_timeout == 1.25
    assert settings.database.neo4j_max_connection_pool_size == 21
    assert settings.database.neo4j_keep_alive is False


def test_invalid_database_env_value_fails_cleanly(tmp_path):
    with pytest.raises(ValueError, match="Invalid integer environment value"):
        load_settings(
            config_path=tmp_path / "missing-config.yaml",
            thresholds_path=tmp_path / "missing-thresholds.yaml",
            environ={"AEGIS_ENV": "test", "REDIS_MAX_CONNECTIONS": "not-an-int"},
        )


def test_redis_connection_pool_uses_configured_parameters(monkeypatch):
    redis_client._redis_pool = None
    pool = MagicMock()
    mock_settings = SimpleNamespace(database=_make_database_settings(
        redis_max_connections=23,
        redis_socket_timeout=1.75,
        redis_socket_connect_timeout=0.5,
        redis_retry_on_timeout=True,
        redis_health_check_interval=30,
        redis_socket_keepalive=True,
    ))

    with patch("src.utils.redis_client.get_settings", return_value=mock_settings), patch(
        "src.utils.redis_client.redis.ConnectionPool.from_url", return_value=pool
    ) as mock_pool, patch("src.utils.redis_client.redis.Redis", return_value=MagicMock()) as mock_redis:
        client = redis_client.get_redis_client("redis://example.invalid/0")

    mock_pool.assert_called_once_with(
        "redis://example.invalid/0",
        decode_responses=True,
        max_connections=23,
        socket_timeout=1.75,
        socket_connect_timeout=0.5,
        retry_on_timeout=True,
        health_check_interval=30,
        socket_keepalive=True,
    )
    mock_redis.assert_called_once_with(connection_pool=pool)
    assert client is not None


def test_redis_connection_pool_reuses_singleton(monkeypatch):
    redis_client._redis_pool = None
    pool = MagicMock()
    mock_redis_instance = MagicMock()
    mock_settings = SimpleNamespace(database=_make_database_settings())

    with patch("src.utils.redis_client.get_settings", return_value=mock_settings), patch(
        "src.utils.redis_client.redis.ConnectionPool.from_url", return_value=pool
    ) as mock_pool, patch("src.utils.redis_client.redis.Redis", return_value=mock_redis_instance):
        redis_client.get_redis_client("redis://example.invalid/0")
        redis_client.get_redis_client("redis://another.example.invalid/1")

    mock_pool.assert_called_once()
    assert redis_client._redis_pool is pool


def test_redis_graph_cache_uses_configured_pool_options():
    mock_settings = SimpleNamespace(database=_make_database_settings(
        redis_max_connections=9,
        redis_socket_timeout=2.0,
        redis_retry_on_timeout=True,
    ))
    mock_client = MagicMock()
    mock_client.ping.return_value = True

    with patch("src.utils.cache.get_settings", return_value=mock_settings), patch(
        "src.utils.cache.redis.Redis.from_url", return_value=mock_client
    ) as mock_from_url:
        cache = RedisGraphCache("redis://cache.example.invalid/0")

    mock_from_url.assert_called_once_with(
        "redis://cache.example.invalid/0",
        decode_responses=False,
        max_connections=9,
        socket_timeout=2.0,
        retry_on_timeout=True,
        socket_keepalive=False,
    )
    assert cache.client is mock_client
