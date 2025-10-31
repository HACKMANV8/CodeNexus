"""
Attack-related data models for threat intelligence and analysis
"""

from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum

class AttackCategory(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_control"
    ACTIONS_OBJECTIVES = "actions_objectives"

class TTPCategory(str, Enum):
    TA0043 = "reconnaissance"
    TA0042 = "resource_development"
    TA0001 = "initial_access"
    TA0002 = "execution"
    TA0003 = "persistence"
    TA0004 = "privilege_escalation"
    TA0005 = "defense_evasion"
    TA0006 = "credential_access"
    TA0007 = "discovery"
    TA0008 = "lateral_movement"
    TA0009 = "collection"
    TA0011 = "command_and_control"
    TA0010 = "exfiltration"
    TA0040 = "impact"

class AttackPattern(BaseModel):
    pattern_id: str
    name: str
    description: str
    category: AttackCategory
    severity: str
    indicators: List[str]
    mitigation: List[str]
    detection_rules: List[str]

class BehavioralSignature(BaseModel):
    signature_id: str
    name: str
    description: str
    patterns: List[str]
    confidence: float
    false_positive_rate: float
    detection_logic: Dict[str, Any]
    required_events: int

class TTPMapping(BaseModel):
    mitre_technique_id: str
    technique_name: str
    tactic: TTPCategory
    description: str
    detection_rules: List[str]
    honeypot_indicators: List[str]
    severity: str

class IOCType(str, Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    USER_AGENT = "user_agent"

class IOC(BaseModel):
    ioc_id: str
    type: IOCType
    value: str
    source: str
    first_seen: datetime
    last_seen: datetime
    confidence: float
    tags: List[str]
    description: Optional[str]
    related_attacks: List[str]

class AttackTimeline(BaseModel):
    timeline_id: str
    attacker_ip: str
    start_time: datetime
    end_time: datetime
    events: List[Dict[str, Any]]
    attack_sequence: List[str]
    techniques_used: List[str]
    risk_score: float
    duration_seconds: float