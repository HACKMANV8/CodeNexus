"""
Rate Limiting Service
API and request rate limiting
"""

import logging
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

from app.core.cache import cache_manager

logger = logging.getLogger(__name__)

class RateLimiterService:
    def __init__(self):
        self.cache = cache_manager
        self.default_limits = {
            'api': {'requests': 1000, 'window': 3600},
            'auth': {'requests': 10, 'window': 300},
            'honeypot': {'requests': 10000, 'window': 3600},
            'ml': {'requests': 500, 'window': 3600}
        }

    async def check_rate_limit(self, identifier: str, category: str = 'api') -> Dict[str, Any]:
        try:
            limit_config = self.default_limits.get(category, self.default_limits['api'])
            max_requests = limit_config['requests']
            window_seconds = limit_config['window']
            
            cache_key = f"rate_limit:{category}:{identifier}"
            current_time = time.time()
            window_start = current_time - window_seconds
            
            requests = self.cache.get(cache_key) or []
            requests = [req_time for req_time in requests if req_time > window_start]
            
            if len(requests) >= max_requests:
                return {
                    'allowed': False,
                    'limit': max_requests,
                    'remaining': 0,
                    'reset_time': int(window_start + window_seconds),
                    'retry_after': int((window_start + window_seconds) - current_time),
                    'current_requests': len(requests)
                }
            
            return {
                'allowed': True,
                'limit': max_requests,
                'remaining': max_requests - len(requests),
                'reset_time': int(window_start + window_seconds),
                'retry_after': 0,
                'current_requests': len(requests)
            }
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return {
                'allowed': True,
                'limit': 1000,
                'remaining': 1000,
                'reset_time': int(time.time() + 3600),
                'error': str(e)
            }

    async def record_request(self, identifier: str, category: str = 'api') -> bool:
        try:
            cache_key = f"rate_limit:{category}:{identifier}"
            current_time = time.time()
            
            requests = self.cache.get(cache_key) or []
            requests.append(current_time)
            
            limit_config = self.default_limits.get(category, self.default_limits['api'])
            window_seconds = limit_config['window']
            
            self.cache.set(cache_key, requests, window_seconds)
            return True
            
        except Exception as e:
            logger.error(f"Failed to record request: {e}")
            return False

    async def get_rate_limit_status(self, identifier: str, category: str = 'api') -> Dict[str, Any]:
        limit_info = await self.check_rate_limit(identifier, category)
        
        return {
            'identifier': identifier,
            'category': category,
            'is_limited': not limit_info['allowed'],
            'current_usage': limit_info['current_requests'],
            'limit': limit_info['limit'],
            'remaining': limit_info['remaining'],
            'reset_time': limit_info['reset_time'],
            'window_seconds': self.default_limits.get(category, {}).get('window', 3600)
        }

    async def get_global_rate_limits(self) -> Dict[str, Any]:
        return {
            'default_limits': self.default_limits,
            'total_categories': len(self.default_limits),
            'cache_backend': self.cache.get_stats().get('type', 'unknown')
        }

    def set_custom_limit(self, category: str, requests: int, window_seconds: int):
        self.default_limits[category] = {
            'requests': requests,
            'window': window_seconds
        }
        logger.info(f"Set custom rate limit for {category}: {requests} requests per {window_seconds} seconds")

    async def reset_rate_limit(self, identifier: str, category: str = 'api') -> bool:
        try:
            cache_key = f"rate_limit:{category}:{identifier}"
            self.cache.delete(cache_key)
            logger.info(f"Reset rate limit for {identifier} in category {category}")
            return True
        except Exception as e:
            logger.error(f"Failed to reset rate limit: {e}")
            return False

    async def get_top_limited_identifiers(self, category: str = 'api', limit: int = 10) -> List[Dict[str, Any]]:
        try:
            pattern = f"rate_limit:{category}:*"
            keys = self.cache.clear_pattern(pattern.replace('*', ''))
            
            limited_identifiers = []
            
            for key in keys[:limit]:
                identifier = key.split(':')[-1]
                status = await self.get_rate_limit_status(identifier, category)
                if status['is_limited']:
                    limited_identifiers.append(status)
            
            return sorted(limited_identifiers, key=lambda x: x['current_usage'], reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to get top limited identifiers: {e}")
            return []

    def get_service_status(self) -> Dict[str, Any]:
        return {
            'status': 'active',
            'cache_enabled': True,
            'categories_configured': list(self.default_limits.keys()),
            'total_limits': len(self.default_limits)
        }

rate_limiter_service = RateLimiterService()

async def check_rate_limit(identifier: str, category: str = 'api') -> Dict[str, Any]:
    return await rate_limiter_service.check_rate_limit(identifier, category)

async def record_request(identifier: str, category: str = 'api') -> bool:
    return await rate_limiter_service.record_request(identifier, category)