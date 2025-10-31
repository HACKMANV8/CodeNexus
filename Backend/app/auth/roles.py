"""
Role-Based Access Control (RBAC)
User roles, permissions, and authorization checks
"""

import logging
from enum import Enum
from typing import List, Dict, Any, Set
from functools import wraps
from fastapi import HTTPException, status, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.database_models import User

logger = logging.getLogger(__name__)

class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_CLIENT = "api_client"

class Permission(str, Enum):
    # System permissions
    VIEW_SYSTEM = "view_system"
    MANAGE_SYSTEM = "manage_system"
    
    # User management permissions
    VIEW_USERS = "view_users"
    MANAGE_USERS = "manage_users"
    
    # Honeypot permissions
    VIEW_HONEYPOTS = "view_honeypots"
    MANAGE_HONEYPOTS = "manage_honeypots"
    
    # Attack data permissions
    VIEW_ATTACKS = "view_attacks"
    ANALYZE_ATTACKS = "analyze_attacks"
    EXPORT_ATTACKS = "export_attacks"
    
    # Response actions permissions
    VIEW_RESPONSES = "view_responses"
    EXECUTE_RESPONSES = "execute_responses"
    APPROVE_RESPONSES = "approve_responses"
    
    # ML model permissions
    VIEW_ML_MODELS = "view_ml_models"
    MANAGE_ML_MODELS = "manage_ml_models"
    TRAIN_MODELS = "train_models"
    
    # Threat intelligence permissions
    VIEW_THREAT_INTEL = "view_threat_intel"
    MANAGE_THREAT_INTEL = "manage_threat_intel"
    
    # API permissions
    USE_API = "use_api"
    MANAGE_API_KEYS = "manage_api_keys"

class RoleManager:
    def __init__(self):
        self.role_permissions = self._initialize_role_permissions()

    def _initialize_role_permissions(self) -> Dict[UserRole, Set[Permission]]:
        return {
            UserRole.ADMIN: {
                Permission.VIEW_SYSTEM,
                Permission.MANAGE_SYSTEM,
                Permission.VIEW_USERS,
                Permission.MANAGE_USERS,
                Permission.VIEW_HONEYPOTS,
                Permission.MANAGE_HONEYPOTS,
                Permission.VIEW_ATTACKS,
                Permission.ANALYZE_ATTACKS,
                Permission.EXPORT_ATTACKS,
                Permission.VIEW_RESPONSES,
                Permission.EXECUTE_RESPONSES,
                Permission.APPROVE_RESPONSES,
                Permission.VIEW_ML_MODELS,
                Permission.MANAGE_ML_MODELS,
                Permission.TRAIN_MODELS,
                Permission.VIEW_THREAT_INTEL,
                Permission.MANAGE_THREAT_INTEL,
                Permission.USE_API,
                Permission.MANAGE_API_KEYS
            },
            UserRole.ANALYST: {
                Permission.VIEW_SYSTEM,
                Permission.VIEW_HONEYPOTS,
                Permission.VIEW_ATTACKS,
                Permission.ANALYZE_ATTACKS,
                Permission.EXPORT_ATTACKS,
                Permission.VIEW_RESPONSES,
                Permission.EXECUTE_RESPONSES,
                Permission.VIEW_ML_MODELS,
                Permission.TRAIN_MODELS,
                Permission.VIEW_THREAT_INTEL,
                Permission.USE_API
            },
            UserRole.VIEWER: {
                Permission.VIEW_SYSTEM,
                Permission.VIEW_HONEYPOTS,
                Permission.VIEW_ATTACKS,
                Permission.VIEW_RESPONSES,
                Permission.VIEW_ML_MODELS,
                Permission.VIEW_THREAT_INTEL
            },
            UserRole.API_CLIENT: {
                Permission.VIEW_ATTACKS,
                Permission.ANALYZE_ATTACKS,
                Permission.VIEW_ML_MODELS,
                Permission.VIEW_THREAT_INTEL,
                Permission.USE_API
            }
        }

    def get_user_permissions(self, role: UserRole) -> Set[Permission]:
        return self.role_permissions.get(role, set())

    def has_permission(self, role: UserRole, permission: Permission) -> bool:
        permissions = self.get_user_permissions(role)
        return permission in permissions

    def can_access_feature(self, role: UserRole, feature: str) -> bool:
        feature_permission_map = {
            "dashboard": Permission.VIEW_SYSTEM,
            "attack_monitoring": Permission.VIEW_ATTACKS,
            "attack_analysis": Permission.ANALYZE_ATTACKS,
            "response_management": Permission.VIEW_RESPONSES,
            "honeypot_management": Permission.VIEW_HONEYPOTS,
            "ml_models": Permission.VIEW_ML_MODELS,
            "threat_intelligence": Permission.VIEW_THREAT_INTEL,
            "user_management": Permission.VIEW_USERS,
            "system_settings": Permission.MANAGE_SYSTEM
        }
        
        required_permission = feature_permission_map.get(feature)
        if not required_permission:
            return False
        
        return self.has_permission(role, required_permission)

    def get_accessible_features(self, role: UserRole) -> List[str]:
        features = [
            "dashboard", "attack_monitoring", "attack_analysis",
            "response_management", "honeypot_management", "ml_models",
            "threat_intelligence", "user_management", "system_settings"
        ]
        
        return [feature for feature in features if self.can_access_feature(role, feature)]

    def validate_user_access(self, user_role: UserRole, required_permission: Permission) -> bool:
        if not self.has_permission(user_role, required_permission):
            logger.warning(f"User with role {user_role} denied access to {required_permission}")
            return False
        return True

    def get_role_hierarchy(self) -> Dict[UserRole, List[UserRole]]:
        return {
            UserRole.ADMIN: [UserRole.ANALYST, UserRole.VIEWER, UserRole.API_CLIENT],
            UserRole.ANALYST: [UserRole.VIEWER, UserRole.API_CLIENT],
            UserRole.VIEWER: [UserRole.API_CLIENT],
            UserRole.API_CLIENT: []
        }

    def can_manage_role(self, user_role: UserRole, target_role: UserRole) -> bool:
        hierarchy = self.get_role_hierarchy()
        manageable_roles = hierarchy.get(user_role, [])
        return target_role in manageable_roles or user_role == target_role

role_manager = RoleManager()

def requires_roles(required_roles: List[UserRole]):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            user_role = current_user.get('role')
            if user_role not in required_roles:
                logger.warning(f"User {current_user.get('username')} with role {user_role} attempted to access {func.__name__}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def requires_permission(required_permission: Permission):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            user_role = current_user.get('role')
            if not role_manager.has_permission(UserRole(user_role), required_permission):
                logger.warning(f"User {current_user.get('username')} denied permission {required_permission}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

async def get_user_permissions(current_user: dict, db: Session = Depends(get_db)) -> Dict[str, Any]:
    user_role = UserRole(current_user.get('role', UserRole.VIEWER))
    permissions = role_manager.get_user_permissions(user_role)
    features = role_manager.get_accessible_features(user_role)
    
    return {
        "role": user_role.value,
        "permissions": [perm.value for perm in permissions],
        "accessible_features": features,
        "can_manage_system": role_manager.has_permission(user_role, Permission.MANAGE_SYSTEM)
    }

async def validate_api_key_permissions(api_key: str, required_permission: Permission, db: Session = Depends(get_db)) -> bool:
    user = db.query(User).filter(User.api_key == api_key, User.is_active == True).first()
    
    if not user:
        return False
    
    return role_manager.has_permission(UserRole(user.role), required_permission)