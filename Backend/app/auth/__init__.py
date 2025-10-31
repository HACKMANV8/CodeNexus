"""
Honeypot CTDR - Authentication Module
JWT-based authentication, role management, and security middleware
"""

from app.auth.jwt_handler import JWTManager
from app.auth.security import SecurityManager
from app.auth.roles import RoleManager, UserRole
from app.auth.middleware import AuthMiddleware

from app.auth.jwt_handler import create_access_token, create_refresh_token, verify_token
from app.auth.security import hash_password, verify_password, generate_api_key
from app.auth.roles import requires_roles, get_user_permissions
from app.auth.middleware import setup_auth_middleware

__all__ = [
    "JWTManager",
    "SecurityManager", 
    "RoleManager",
    "UserRole",
    "AuthMiddleware",
    "create_access_token",
    "create_refresh_token", 
    "verify_token",
    "hash_password",
    "verify_password",
    "generate_api_key",
    "requires_roles",
    "get_user_permissions",
    "setup_auth_middleware"
]