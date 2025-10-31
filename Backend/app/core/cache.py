"""
Cache management for Honeypot CTDR System
Redis-based caching with fallback to in-memory cache
"""

import redis
from typing import Any, Optional, Union
import json
import pickle
import logging
from datetime import timedelta
import time

from app.core.config import settings

logger = logging.getLogger(__name__)

class CacheManager:
    """Cache management with Redis and fallback support"""
    
    def __init__(self):
        self.redis_client = None
        self.fallback_cache = {}
        self.use_redis = False
        self._setup_cache()
    
    def _setup_cache(self):
        """Setup Redis connection or fallback to in-memory cache"""
        try:
            if settings.CACHE.REDIS_URL:
                self.redis_client = redis.from_url(
                    settings.CACHE.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5
                )
                # Test connection
                self.redis_client.ping()
                self.use_redis = True
                logger.info("Redis cache initialized successfully")
            else:
                logger.warning("Redis URL not configured, using in-memory cache")
                
        except Exception as e:
            logger.warning(f"Redis connection failed, using in-memory cache: {e}")
            self.use_redis = False
    
    def _make_key(self, key: str) -> str:
        """Create namespaced cache key"""
        return f"{settings.CACHE.KEY_PREFIX}:{key}"
    
    def set(
        self, 
        key: str, 
        value: Any, 
        expire: Optional[int] = None
    ) -> bool:
        """Set cache value with optional expiration"""
        try:
            cache_key = self._make_key(key)
            
            if expire is None:
                expire = settings.CACHE.DEFAULT_TIMEOUT
            
            if self.use_redis and self.redis_client:
                # Serialize value for Redis
                if isinstance(value, (dict, list)):
                    serialized_value = json.dumps(value)
                else:
                    serialized_value = str(value)
                
                self.redis_client.setex(
                    cache_key, 
                    expire, 
                    serialized_value
                )
            else:
                # Store in memory with expiration
                self.fallback_cache[cache_key] = {
                    'value': value,
                    'expire_at': time.time() + expire if expire else None
                }
            
            return True
            
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False
    
    def get(self, key: str) -> Optional[Any]:
        """Get cache value"""
        try:
            cache_key = self._make_key(key)
            
            if self.use_redis and self.redis_client:
                value = self.redis_client.get(cache_key)
                if value:
                    # Try to deserialize JSON
                    try:
                        return json.loads(value)
                    except json.JSONDecodeError:
                        return value
            else:
                # Check in-memory cache
                if cache_key in self.fallback_cache:
                    item = self.fallback_cache[cache_key]
                    # Check expiration
                    if item['expire_at'] and time.time() > item['expire_at']:
                        del self.fallback_cache[cache_key]
                        return None
                    return item['value']
            
            return None
            
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete cache key"""
        try:
            cache_key = self._make_key(key)
            
            if self.use_redis and self.redis_client:
                return bool(self.redis_client.delete(cache_key))
            else:
                if cache_key in self.fallback_cache:
                    del self.fallback_cache[cache_key]
                    return True
                return False
                
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            cache_key = self._make_key(key)
            
            if self.use_redis and self.redis_client:
                return bool(self.redis_client.exists(cache_key))
            else:
                if cache_key in self.fallback_cache:
                    item = self.fallback_cache[cache_key]
                    if item['expire_at'] and time.time() > item['expire_at']:
                        del self.fallback_cache[cache_key]
                        return False
                    return True
                return False
                
        except Exception as e:
            logger.error(f"Cache exists error: {e}")
            return False
    
    def clear_pattern(self, pattern: str) -> int:
        """Clear keys matching pattern"""
        try:
            full_pattern = self._make_key(pattern)
            
            if self.use_redis and self.redis_client:
                keys = self.redis_client.keys(full_pattern)
                if keys:
                    return self.redis_client.delete(*keys)
            else:
                
                count = 0
                keys_to_delete = [
                    key for key in self.fallback_cache.keys() 
                    if full_pattern in key
                ]
                for key in keys_to_delete:
                    del self.fallback_cache[key]
                    count += 1
                return count
                
            return 0
            
        except Exception as e:
            logger.error(f"Cache clear pattern error: {e}")
            return 0
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        try:
            if self.use_redis and self.redis_client:
                info = self.redis_client.info()
                return {
                    "type": "redis",
                    "connected_clients": info.get('connected_clients', 0),
                    "used_memory": info.get('used_memory_human', '0'),
                    "keyspace_hits": info.get('keyspace_hits', 0),
                    "keyspace_misses": info.get('keyspace_misses', 0)
                }
            else:
                return {
                    "type": "memory",
                    "total_keys": len(self.fallback_cache),
                    "expired_keys": len([
                        k for k, v in self.fallback_cache.items() 
                        if v['expire_at'] and time.time() > v['expire_at']
                    ])
                }
                
        except Exception as e:
            logger.error(f"Cache stats error: {e}")
            return {"error": str(e)}

cache_manager = CacheManager()

def get_cache() -> CacheManager:
    """Get cache manager instance"""
    return cache_manager