"""
API Endpoints Package
All REST API route handlers
"""

from app.api.endpoints.auth import router as auth_router
from app.api.endpoints.attacks import router as attacks_router
from app.api.endpoints.dashboard import router as dashboard_router
from app.api.endpoints.responses import router as responses_router
from app.api.endpoints.ml_models import router as ml_models_router
from app.api.endpoints.threat_intel import router as threat_intel_router

__all__ = [
    "auth_router",
    "attacks_router",
    "dashboard_router",
    "responses_router", 
    "ml_models_router",
    "threat_intel_router"
]