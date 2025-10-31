"""
JWT Token Management
Handles JWT token creation, validation, and refresh
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from jose import JWTError, jwt
from fastapi import HTTPException, status

from app.core.config import settings

logger = logging.getLogger(__name__)

class JWTManager:
    def __init__(self):
        self.secret_key = settings.secret_key
        self.algorithm = settings.algorithm
        self.access_token_expire_minutes = settings.access_token_expire_minutes
        self.refresh_token_expire_days = settings.refresh_token_expire_days

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        try:
            to_encode = data.copy()
            
            if expires_delta:
                expire = datetime.utcnow() + expires_delta
            else:
                expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
            
            to_encode.update({
                "exp": expire,
                "type": "access",
                "iat": datetime.utcnow()
            })
            
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Access token creation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not create access token"
            )

    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        try:
            to_encode = data.copy()
            expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
            
            to_encode.update({
                "exp": expire,
                "type": "refresh",
                "iat": datetime.utcnow()
            })
            
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Refresh token creation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not create refresh token"
            )

    def verify_token(self, token: str) -> Dict[str, Any]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
            
        except JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def refresh_access_token(self, refresh_token: str) -> Dict[str, str]:
        try:
            payload = self.verify_token(refresh_token)
            
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
            
            username = payload.get("sub")
            user_id = payload.get("user_id")
            role = payload.get("role", "viewer")
            
            if not username or not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload"
                )
            
            new_access_token = self.create_access_token({
                "sub": username,
                "user_id": user_id,
                "role": role
            })
            
            return {
                "access_token": new_access_token,
                "token_type": "bearer",
                "expires_in": self.access_token_expire_minutes * 60
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not refresh token"
            )

    def decode_token_without_verification(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload
        except JWTError:
            return None

    def get_token_expiry(self, token: str) -> Optional[datetime]:
        try:
            payload = self.decode_token_without_verification(token)
            if payload and "exp" in payload:
                return datetime.fromtimestamp(payload["exp"])
            return None
        except Exception:
            return None

    def is_token_expired(self, token: str) -> bool:
        expiry = self.get_token_expiry(token)
        if not expiry:
            return True
        return datetime.utcnow() > expiry

jwt_manager = JWTManager()

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    return jwt_manager.create_access_token(data, expires_delta)

def create_refresh_token(data: Dict[str, Any]) -> str:
    return jwt_manager.create_refresh_token(data)

def verify_token(token: str) -> Dict[str, Any]:
    return jwt_manager.verify_token(token)

def refresh_access_token(refresh_token: str) -> Dict[str, str]:
    return jwt_manager.refresh_access_token(refresh_token)