"""
Honeypot CTDR - Core Module
Central configuration and infrastructure components
"""

from app.core.config import settings
from app.core.database import DatabaseManager
from app.core.security import SecurityManager
from app.core.cache import CacheManager

__all__ = [
    "settings",
    "DatabaseManager", 
    "SecurityManager",
    "CacheManager",
    "get_database",
    "get_cache"
]

db_manager = DatabaseManager()
security_manager = SecurityManager()
cache_manager = CacheManager()

def get_database():
    """Get database session"""
    return db_manager.get_session()

def get_cache():
    """Get cache instance"""
    return cache_manager