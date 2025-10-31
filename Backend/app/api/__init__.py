"""
Honeypot CTDR - API Module
REST API endpoints and WebSocket handlers for frontend communication
"""

from app.api.endpoints.auth import router as auth_router
from app.api.endpoints.attacks import router as attacks_router
from app.api.endpoints.dashboard import router as dashboard_router
from app.api.endpoints.responses import router as responses_router
from app.api.endpoints.ml_models import router as ml_models_router
from app.api.endpoints.threat_intel import router as threat_intel_router

from app.api.websocket import websocket_manager
from app.api.dependencies import get_current_user, get_current_active_user

__all__ = [
    "auth_router",
    "attacks_router",
    "dashboard_router", 
    "responses_router",
    "ml_models_router",
    "threat_intel_router",
    "websocket_manager",
    "get_current_user",
    "get_current_active_user"
]