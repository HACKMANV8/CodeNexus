"""
API Dependencies and Dependency Injection
Common dependencies used across API endpoints
"""

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Generator

from app.core.database import get_db
from app.core.security import security_manager, security_bearer
from app.models.database_models import User

async def get_current_user(
    token: str = Depends(security_bearer)
) -> dict:
    try:
        payload = security_manager.verify_token(token.credentials)
        return payload
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_active_user(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> dict:
    user = db.query(User).filter(User.id == current_user.get("user_id")).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    return {
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active
    }

async def get_admin_user(
    current_user: dict = Depends(get_current_active_user)
) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    return current_user

async def get_analyst_user(
    current_user: dict = Depends(get_current_active_user)
) -> dict:
    if current_user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    return current_user

def get_websocket_manager():
    from app.api.websocket import websocket_manager
    return websocket_manager

def get_classification_engine():
    from app.pipeline.classify import ClassificationEngine
    return ClassificationEngine()

def get_prediction_engine():
    from app.pipeline.predictor import PredictionEngine
    return PredictionEngine()

def get_response_engine():
    from app.pipeline.responder import ResponseEngine
    return ResponseEngine()

def get_analysis_engine():
    from app.pipeline.analyzer import AnalysisEngine
    return AnalysisEngine()

def get_honeypot_factory():
    from app.honeypots.factory import HoneypotFactory
    return HoneypotFactory()