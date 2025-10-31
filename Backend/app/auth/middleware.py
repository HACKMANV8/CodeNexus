"""
Authentication Middleware
Request authentication, rate limiting, and security headers
"""

import logging
import time
from typing import Dict, Any, Optional, Callable
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.auth.jwt_handler import jwt_manager
from app.auth.roles import role_manager, UserRole, Permission
from app.core.config import settings

logger = logging.getLogger(__name__)

security_bearer = HTTPBearer()

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.rate_limits = {}
        self.rate_limit_window = 3600
        self.max_requests_per_hour = 1000

    async def dispatch(self, request: Request, call_next: Callable):
        start_time = time.time()
        
        try:
            response = await self._process_request(request, call_next)
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Middleware error: {e}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error"}
            )
        finally:
            process_time = time.time() - start_time
            logger.debug(f"Request processed in {process_time:.2f}s")

    async def _process_request(self, request: Request, call_next: Callable):
        client_ip = self._get_client_ip(request)
        
        if not await self._check_rate_limit(client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded"}
            )
        
        await self._authenticate_request(request)
        
        response = await call_next(request)
        
        response = self._add_security_headers(response)
        
        return response

    def _get_client_ip(self, request: Request) -> str:
        if "x-forwarded-for" in request.headers:
            return request.headers["x-forwarded-for"].split(",")[0].strip()
        return request.client.host

    async def _check_rate_limit(self, client_ip: str) -> bool:
        current_time = time.time()
        window_start = current_time - self.rate_limit_window
        
        if client_ip not in self.rate_limits:
            self.rate_limits[client_ip] = []
        
        requests = self.rate_limits[client_ip]
        requests = [req_time for req_time in requests if req_time > window_start]
        
        if len(requests) >= self.max_requests_per_hour:
            return False
        
        requests.append(current_time)
        self.rate_limits[client_ip] = requests
        
        return True

    async def _authenticate_request(self, request: Request):
        if request.url.path.startswith("/api/docs") or request.url.path.startswith("/api/redoc"):
            return
        
        if request.url.path.startswith("/api/"):
            await self._authenticate_api_request(request)

    async def _authenticate_api_request(self, request: Request):
        if request.method == "OPTIONS":
            return
        
        public_endpoints = [
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh",
            "/api/health"
        ]
        
        if any(request.url.path.startswith(endpoint) for endpoint in public_endpoints):
            return
        
        auth_header = request.headers.get("authorization")
        
        if not auth_header:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        try:
            scheme, credentials = auth_header.split()
            if scheme.lower() != "bearer":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication scheme",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            payload = jwt_manager.verify_token(credentials)
            request.state.user = payload
            
            await self._validate_user_permissions(request, payload)
            
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def _validate_user_permissions(self, request: Request, user_payload: Dict[str, Any]):
        user_role = user_payload.get("role", UserRole.VIEWER)
        
        required_permission = self._get_required_permission(request)
        if required_permission and not role_manager.has_permission(UserRole(user_role), required_permission):
            logger.warning(f"User {user_payload.get('sub')} denied access to {request.url.path}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )

    def _get_required_permission(self, request: Request) -> Optional[Permission]:
        path = request.url.path
        method = request.method
        
        permission_map = {
            ("GET", "/api/v1/users"): Permission.VIEW_USERS,
            ("POST", "/api/v1/users"): Permission.MANAGE_USERS,
            ("PUT", "/api/v1/users"): Permission.MANAGE_USERS,
            ("DELETE", "/api/v1/users"): Permission.MANAGE_USERS,
            
            ("GET", "/api/v1/honeypots"): Permission.VIEW_HONEYPOTS,
            ("POST", "/api/v1/honeypots"): Permission.MANAGE_HONEYPOTS,
            ("PUT", "/api/v1/honeypots"): Permission.MANAGE_HONEYPOTS,
            ("DELETE", "/api/v1/honeypots"): Permission.MANAGE_HONEYPOTS,
            
            ("GET", "/api/v1/attacks"): Permission.VIEW_ATTACKS,
            ("POST", "/api/v1/attacks/analyze"): Permission.ANALYZE_ATTACKS,
            ("POST", "/api/v1/attacks/export"): Permission.EXPORT_ATTACKS,
            
            ("GET", "/api/v1/responses"): Permission.VIEW_RESPONSES,
            ("POST", "/api/v1/responses"): Permission.EXECUTE_RESPONSES,
            ("POST", "/api/v1/responses/approve"): Permission.APPROVE_RESPONSES,
            
            ("GET", "/api/v1/ml"): Permission.VIEW_ML_MODELS,
            ("POST", "/api/v1/ml/train"): Permission.TRAIN_MODELS,
            ("PUT", "/api/v1/ml"): Permission.MANAGE_ML_MODELS,
            
            ("GET", "/api/v1/threat-intel"): Permission.VIEW_THREAT_INTEL,
            ("POST", "/api/v1/threat-intel"): Permission.MANAGE_THREAT_INTEL,
            ("DELETE", "/api/v1/threat-intel"): Permission.MANAGE_THREAT_INTEL,
            
            ("GET", "/api/v1/system"): Permission.VIEW_SYSTEM,
            ("PUT", "/api/v1/system"): Permission.MANAGE_SYSTEM,
        }
        
        for (req_method, req_path), permission in permission_map.items():
            if method == req_method and path.startswith(req_path):
                return permission
        
        return None

    def _add_security_headers(self, response):
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response

    def get_rate_limit_stats(self, client_ip: str) -> Dict[str, Any]:
        if client_ip not in self.rate_limits:
            return {"requests": 0, "remaining": self.max_requests_per_hour}
        
        current_time = time.time()
        window_start = current_time - self.rate_limit_window
        
        requests = [req_time for req_time in self.rate_limits[client_ip] if req_time > window_start]
        request_count = len(requests)
        remaining = max(0, self.max_requests_per_hour - request_count)
        
        return {
            "requests": request_count,
            "remaining": remaining,
            "reset_time": int(window_start + self.rate_limit_window)
        }

class CORSMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            response = JSONResponse(content={})
        else:
            response = await call_next(request)
        
        origin = request.headers.get("origin")
        if origin in settings.cors_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
            response.headers["Access-Control-Allow-Credentials"] = "true"
        
        return response

async def get_current_user(request: Request) -> Dict[str, Any]:
    if not hasattr(request.state, 'user'):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return request.state.user

async def get_current_active_user(request: Request) -> Dict[str, Any]:
    user = await get_current_user(request)
    
    if not user.get('active', True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    return user

def setup_auth_middleware(app: ASGIApp):
    app.add_middleware(AuthMiddleware)
    app.add_middleware(CORSMiddleware)
    
    logger.info("Authentication middleware configured")

def get_auth_middleware() -> AuthMiddleware:
    return AuthMiddleware