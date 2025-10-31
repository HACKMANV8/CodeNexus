"""
Security Utilities
Password hashing, API key generation, and security validation
"""

import logging
import secrets
import string
from typing import Optional
from passlib.context import CryptContext
from fastapi import HTTPException, status

from app.core.config import settings

logger = logging.getLogger(__name__)

class SecurityManager:
    def __init__(self):
        self.pwd_context = CryptContext(
            schemes=["bcrypt"], 
            deprecated="auto",
            bcrypt__rounds=settings.password_hash_rounds
        )
        self.api_key_length = 32
        self.password_min_length = 8

    def hash_password(self, password: str) -> str:
        try:
            if not self._validate_password_strength(password):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password does not meet security requirements"
                )
            
            return self.pwd_context.hash(password)
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Password hashing failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not hash password"
            )

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        try:
            return self.pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False

    def generate_api_key(self, prefix: str = "hp") -> str:
        try:
            alphabet = string.ascii_letters + string.digits
            random_part = ''.join(secrets.choice(alphabet) for _ in range(self.api_key_length))
            return f"{prefix}_{random_part}"
            
        except Exception as e:
            logger.error(f"API key generation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not generate API key"
            )

    def generate_secure_random_string(self, length: int = 16) -> str:
        try:
            alphabet = string.ascii_letters + string.digits
            return ''.join(secrets.choice(alphabet) for _ in range(length))
        except Exception as e:
            logger.error(f"Random string generation failed: {e}")
            return ""

    def _validate_password_strength(self, password: str) -> bool:
        if len(password) < self.password_min_length:
            return False
        
        if not any(c.isupper() for c in password):
            return False
        
        if not any(c.islower() for c in password):
            return False
        
        if not any(c.isdigit() for c in password):
            return False
        
        if not any(c in string.punctuation for c in password):
            return False
        
        return True

    def validate_password_policy(self, password: str) -> Dict[str, Any]:
        checks = {
            "min_length": len(password) >= self.password_min_length,
            "has_uppercase": any(c.isupper() for c in password),
            "has_lowercase": any(c.islower() for c in password),
            "has_digit": any(c.isdigit() for c in password),
            "has_special": any(c in string.punctuation for c in password),
            "not_common": password.lower() not in self._get_common_passwords()
        }
        
        is_valid = all(checks.values())
        score = sum(checks.values())
        
        return {
            "is_valid": is_valid,
            "score": score,
            "checks": checks,
            "strength": "strong" if score >= 5 else "medium" if score >= 4 else "weak"
        }

    def _get_common_passwords(self) -> set:
        return {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master"
        }

    def generate_session_id(self) -> str:
        return self.generate_secure_random_string(32)

    def sanitize_input(self, input_string: str) -> str:
        dangerous_patterns = [
            "<script>", "javascript:", "onload=", "onerror=",
            "eval(", "exec(", "system(", "union select"
        ]
        
        sanitized = input_string
        for pattern in dangerous_patterns:
            sanitized = sanitized.replace(pattern, "")
        
        return sanitized.strip()

    def validate_ip_address(self, ip_address: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def generate_csrf_token(self) -> str:
        return self.generate_secure_random_string(32)

security_manager = SecurityManager()

def hash_password(password: str) -> str:
    return security_manager.hash_password(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return security_manager.verify_password(plain_password, hashed_password)

def generate_api_key(prefix: str = "hp") -> str:
    return security_manager.generate_api_key(prefix)

def validate_password_policy(password: str) -> Dict[str, Any]:
    return security_manager.validate_password_policy(password)