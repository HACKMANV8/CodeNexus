"""
Pydantic Schemas for Honeypot CTDR System
API request/response models
"""

from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRole = UserRole.ANALYST

class UserCreate(UserBase):
    password: str

    @validator('password')
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str
    expires_in: int

class AttackEventBase(BaseModel):
    honeypot_type: str
    source_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    payload: Optional[str]
    method: Optional[str]
    url: Optional[str]
    user_agent: Optional[str]

class AttackEventCreate(AttackEventBase):
    pass

class AttackEventResponse(AttackEventBase):
    id: int
    event_id: str
    timestamp: datetime
    country: Optional[str]
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    asn: Optional[str]
    organization: Optional[str]
    threat_level: str
    ml_confidence: Optional[float]
    is_malicious: bool
    tags: Dict[str, Any]

    class Config:
        from_attributes = True

class AttackEventListResponse(BaseModel):
    total: int
    attacks: List[AttackEventResponse]
    page: int
    size: int

class AttackerProfileResponse(BaseModel):
    id: int
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    attack_count: int
    country: Optional[str]
    asn: Optional[str]
    organization: Optional[str]
    threat_score: int
    is_blocked: bool
    behavior_patterns: Dict[str, Any]
    attack_methods: List[str]
    last_attack_type: Optional[str]

    class Config:
        from_attributes = True

class MLPredictionCreate(BaseModel):
    event_id: str
    model_name: str
    prediction: str
    confidence: float
    features: Dict[str, Any]
    shap_values: Optional[Dict[str, Any]] = None

class MLPredictionResponse(BaseModel):
    id: int
    event_id: str
    model_name: str
    prediction: str
    confidence: float
    features: Dict[str, Any]
    shap_values: Optional[Dict[str, Any]]
    timestamp: datetime
    model_version: Optional[str]

    class Config:
        from_attributes = True

class ResponseActionType(str, Enum):
    BLOCK_IP = "block_ip"
    ALLOW_IP = "allow_ip"
    QUARANTINE = "quarantine"
    ALERT = "alert"
    LOG = "log"

class ResponseActionCreate(BaseModel):
    event_id: str
    attacker_ip: str
    action_type: ResponseActionType
    action_details: Dict[str, Any]
    ttl: Optional[int] = 3600

class ResponseActionResponse(BaseModel):
    id: int
    action_id: str
    event_id: str
    attacker_ip: str
    action_type: str
    action_details: Dict[str, Any]
    status: str
    created_by: Optional[str]
    created_at: datetime
    executed_at: Optional[datetime]
    ttl: Optional[int]

    class Config:
        from_attributes = True

class ThreatIntelCreate(BaseModel):
    ioc_type: str
    ioc_value: str
    source: str
    confidence: float
    tags: Dict[str, Any]
    description: Optional[str]

class ThreatIntelResponse(BaseModel):
    id: int
    ioc_type: str
    ioc_value: str
    source: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    tags: Dict[str, Any]
    description: Optional[str]
    is_active: bool

    class Config:
        from_attributes = True

class SystemHealth(BaseModel):
    status: str
    timestamp: datetime
    database: bool
    ml_models: bool
    honeypots: bool
    cache: bool
    uptime: float
    active_connections: int