import pytest
from unittest.mock import MagicMock, patch
from src.features.lateral_movement import LateralMovementDetector

class FakePipeline:
    def __init__(self, db):
        self.db = db
        self.commands = []
        
    def hincrby(self, key, field, amount):
        self.commands.append(('hincrby', key, field, amount))
        return self
        
    def sadd(self, key, *values):
        self.commands.append(('sadd', key, values))
        return self
        
    def incr(self, key):
        self.commands.append(('incr', key))
        return self
        
    def execute(self):
        for cmd in self.commands:
            op = cmd[0]
            if op == 'hincrby':
                _, key, field, amount = cmd
                if key not in self.db:
                    self.db[key] = {}
                self.db[key][field] = str(int(self.db[key].get(field, 0)) + amount)
            elif op == 'sadd':
                _, key, values = cmd
                if key not in self.db:
                    self.db[key] = set()
                for v in values:
                    self.db[key].add(str(v))
            elif op == 'incr':
                _, key = cmd
                self.db[key] = str(int(self.db.get(key, 0)) + 1)
        return []

class FakeRedis:
    def __init__(self):
        self.db = {}
        self.ttl = {}
        
    def get(self, key):
        return self.db.get(key)
        
    def set(self, key, value):
        self.db[key] = str(value)
        
    def setnx(self, key, value):
        if key not in self.db:
            self.db[key] = str(value)
            return True
        return False
        
    def setex(self, key, ttl, value):
        self.db[key] = str(value)
        self.ttl[key] = ttl
        
    def ping(self):
        return True
        
    def lpush(self, key, value):
        if key not in self.db:
            self.db[key] = []
        self.db[key].insert(0, str(value))
        
    def ltrim(self, key, start, end):
        if key in self.db:
            self.db[key] = self.db[key][start:end+1]
            
    def lrange(self, key, start, end):
        if key not in self.db:
            return []
        return self.db[key][start:end+1]
        
    def hgetall(self, key):
        val = self.db.get(key, {})
        if isinstance(val, set) or isinstance(val, list):
            return {}
        return val
        
    def pipeline(self, transaction=True):
        return FakePipeline(self.db)

def test_redis_cache_hits_and_misses():
    fake_redis = FakeRedis()
    
    with patch("src.features.lateral_movement.get_redis_client", return_value=fake_redis):
        mock_settings = MagicMock()
        mock_settings.innovations.redis_url = "redis://localhost:6379/0"
        with patch("src.features.lateral_movement.get_settings", return_value=mock_settings):
            detector = LateralMovementDetector()
            assert bool(detector.use_redis) is True
            
            # Update graph
            detector.update_graph("A", "B")
            detector.update_graph("B", "C")
            
            # Miss: direct calculation and write to redis
            score1 = detector._calculate_approx_centrality("B")
            assert score1 > 0
            
            # Verify it wrote to redis cache
            redis_cache_key = "aegis:cache:centrality:B"
            assert fake_redis.get(redis_cache_key) is not None
            assert float(fake_redis.get(redis_cache_key)) == score1
            
            # Hit: fetch from redis cache
            # Let's change the value in redis to verify it gets hit from redis
            fake_redis.setex(redis_cache_key, 86400, 999.0)
            detector._centrality_cache.clear() # clear local cache
            
            score2 = detector._calculate_approx_centrality("B")
            assert score2 == 999.0

def test_redis_cache_fallback():
    mock_settings = MagicMock()
    mock_settings.innovations.redis_url = "redis://localhost:6379/0"
    
    with patch("src.features.lateral_movement.get_settings", return_value=mock_settings):
        with patch("src.features.lateral_movement.get_redis_client", side_effect=Exception("Connection Refused")):
            detector = LateralMovementDetector()
            assert detector.use_redis is False
            
            detector.update_graph("A", "B")
            detector.update_graph("B", "C")
            score = detector._calculate_approx_centrality("B")
            assert score > 0
