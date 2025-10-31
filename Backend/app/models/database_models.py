"""
SQLAlchemy Database Models for Honeypot CTDR System
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    role = Column(String(20), default="analyst")
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))
    preferences = Column(JSON, default=dict)

class AttackEvent(Base):
    __tablename__ = "attack_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(50), unique=True, index=True)
    honeypot_type = Column(String(20), nullable=False)
    source_ip = Column(String(45), nullable=False)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    payload = Column(Text)
    method = Column(String(10))
    url = Column(Text)
    user_agent = Column(Text)
    country = Column(String(2))
    city = Column(String(100))
    latitude = Column(Float)
    longitude = Column(Float)
    asn = Column(String(50))
    organization = Column(String(255))
    threat_level = Column(String(20), default="low")
    ml_confidence = Column(Float)
    is_malicious = Column(Boolean, default=False)
    tags = Column(JSON)
    raw_data = Column(JSON)

class AttackerProfile(Base):
    __tablename__ = "attacker_profiles"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True))
    attack_count = Column(Integer, default=0)
    country = Column(String(2))
    asn = Column(String(50))
    organization = Column(String(255))
    threat_score = Column(Integer, default=0)
    is_blocked = Column(Boolean, default=False)
    behavior_patterns = Column(JSON)
    attack_methods = Column(JSON)
    last_attack_type = Column(String(50))

class MLPrediction(Base):
    __tablename__ = "ml_predictions"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(50), index=True)
    model_name = Column(String(50), nullable=False)
    prediction = Column(String(50), nullable=False)
    confidence = Column(Float, nullable=False)
    features = Column(JSON)
    shap_values = Column(JSON)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    model_version = Column(String(20))

class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)
    action_id = Column(String(50), unique=True, index=True)
    event_id = Column(String(50), index=True)
    attacker_ip = Column(String(45), nullable=False)
    action_type = Column(String(20), nullable=False)
    action_details = Column(JSON)
    status = Column(String(20), default="pending")
    created_by = Column(String(50))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    executed_at = Column(DateTime(timezone=True))
    ttl = Column(Integer)

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(20), nullable=False)
    ioc_value = Column(String(500), nullable=False)
    source = Column(String(50))
    confidence = Column(Float)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True))
    tags = Column(JSON)
    description = Column(Text)
    is_active = Column(Boolean, default=True)

class SystemSettings(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    setting_key = Column(String(100), unique=True, index=True, nullable=False)
    setting_value = Column(JSON, nullable=False)
    description = Column(Text)
    updated_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_by = Column(String(50))