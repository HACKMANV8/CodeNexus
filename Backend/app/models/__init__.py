"""
Honeypot CTDR - Models Module
Database models, Pydantic schemas, and ML data structures
"""

from app.models.database_models import (
    User,
    AttackEvent,
    AttackerProfile,
    MLPrediction,
    ResponseAction,
    ThreatIntelligence,
    SystemSettings
)

from app.models.schemas import (
    UserCreate,
    UserResponse,
    UserLogin,
    Token,
    AttackEventCreate,
    AttackEventResponse,
    AttackEventListResponse,
    AttackerProfileResponse,
    MLPredictionCreate,
    MLPredictionResponse,
    ResponseActionCreate,
    ResponseActionResponse,
    ThreatIntelCreate,
    ThreatIntelResponse,
    SystemHealth
)

from app.models.attack_models import (
    AttackPattern,
    BehavioralSignature,
    TTPMapping,
    IOC,
    AttackTimeline
)

from app.models.ml_models import (
    MLFeatureSet,
    ModelPrediction,
    SHAPExplanation,
    ModelPerformance,
    TrainingMetrics
)

__all__ = [
    # Database Models
    "User",
    "AttackEvent",
    "AttackerProfile",
    "MLPrediction",
    "ResponseAction",
    "ThreatIntelligence",
    "SystemSettings",
    
    # Pydantic Schemas
    "UserCreate",
    "UserResponse",
    "UserLogin",
    "Token",
    "AttackEventCreate",
    "AttackEventResponse",
    "AttackEventListResponse",
    "AttackerProfileResponse",
    "MLPredictionCreate",
    "MLPredictionResponse",
    "ResponseActionCreate",
    "ResponseActionResponse",
    "ThreatIntelCreate",
    "ThreatIntelResponse",
    "SystemHealth",
    
    # Attack Models
    "AttackPattern",
    "BehavioralSignature",
    "TTPMapping",
    "IOC",
    "AttackTimeline",
    
    # ML Models
    "MLFeatureSet",
    "ModelPrediction",
    "SHAPExplanation",
    "ModelPerformance",
    "TrainingMetrics"
]