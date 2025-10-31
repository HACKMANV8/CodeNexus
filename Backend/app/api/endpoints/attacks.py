"""
Attack Events API Endpoints
Real-time attack data and historical analysis
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.database_models import AttackEvent, AttackerProfile
from app.models.schemas import AttackEventResponse, AttackEventListResponse, AttackerProfileResponse
from app.pipeline.analyzer import analyze_attack_patterns

router = APIRouter()

@router.get("/live", response_model=List[AttackEventResponse])
async def get_live_attacks(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=1000),
    honeypot_type: Optional[str] = None,
    threat_level: Optional[str] = None
):
    query = db.query(AttackEvent)
    
    if honeypot_type:
        query = query.filter(AttackEvent.honeypot_type == honeypot_type)
    
    if threat_level:
        query = query.filter(AttackEvent.threat_level == threat_level)
    
    attacks = query.order_by(AttackEvent.timestamp.desc()).limit(limit).all()
    
    return [
        AttackEventResponse(
            id=attack.id,
            event_id=attack.event_id,
            honeypot_type=attack.honeypot_type,
            source_ip=attack.source_ip,
            source_port=attack.source_port,
            destination_port=attack.destination_port,
            timestamp=attack.timestamp,
            payload=attack.payload,
            method=attack.method,
            url=attack.url,
            user_agent=attack.user_agent,
            country=attack.country,
            city=attack.city,
            latitude=attack.latitude,
            longitude=attack.longitude,
            asn=attack.asn,
            organization=attack.organization,
            threat_level=attack.threat_level,
            ml_confidence=attack.ml_confidence,
            is_malicious=attack.is_malicious,
            tags=attack.tags or {}
        )
        for attack in attacks
    ]

@router.get("/history", response_model=AttackEventListResponse)
async def get_attack_history(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    source_ip: Optional[str] = None,
    honeypot_type: Optional[str] = None
):
    query = db.query(AttackEvent)
    
    if start_date:
        query = query.filter(AttackEvent.timestamp >= start_date)
    
    if end_date:
        query = query.filter(AttackEvent.timestamp <= end_date)
    
    if source_ip:
        query = query.filter(AttackEvent.source_ip == source_ip)
    
    if honeypot_type:
        query = query.filter(AttackEvent.honeypot_type == honeypot_type)
    
    total = query.count()
    attacks = query.order_by(AttackEvent.timestamp.desc()).offset((page - 1) * size).limit(size).all()
    
    attack_responses = [
        AttackEventResponse(
            id=attack.id,
            event_id=attack.event_id,
            honeypot_type=attack.honeypot_type,
            source_ip=attack.source_ip,
            source_port=attack.source_port,
            destination_port=attack.destination_port,
            timestamp=attack.timestamp,
            payload=attack.payload,
            method=attack.method,
            url=attack.url,
            user_agent=attack.user_agent,
            country=attack.country,
            city=attack.city,
            latitude=attack.latitude,
            longitude=attack.longitude,
            asn=attack.asn,
            organization=attack.organization,
            threat_level=attack.threat_level,
            ml_confidence=attack.ml_confidence,
            is_malicious=attack.is_malicious,
            tags=attack.tags or {}
        )
        for attack in attacks
    ]
    
    return AttackEventListResponse(
        total=total,
        attacks=attack_responses,
        page=page,
        size=size
    )

@router.get("/{event_id}", response_model=AttackEventResponse)
async def get_attack_details(
    event_id: str,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    attack = db.query(AttackEvent).filter(AttackEvent.event_id == event_id).first()
    
    if not attack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack event not found"
        )
    
    return AttackEventResponse(
        id=attack.id,
        event_id=attack.event_id,
        honeypot_type=attack.honeypot_type,
        source_ip=attack.source_ip,
        source_port=attack.source_port,
        destination_port=attack.destination_port,
        timestamp=attack.timestamp,
        payload=attack.payload,
        method=attack.method,
        url=attack.url,
        user_agent=attack.user_agent,
        country=attack.country,
        city=attack.city,
        latitude=attack.latitude,
        longitude=attack.longitude,
        asn=attack.asn,
        organization=attack.organization,
        threat_level=attack.threat_level,
        ml_confidence=attack.ml_confidence,
        is_malicious=attack.is_malicious,
        tags=attack.tags or {}
    )

@router.get("/attackers/profiles", response_model=List[AttackerProfileResponse])
async def get_attacker_profiles(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    min_attacks: int = Query(1, ge=1),
    is_blocked: Optional[bool] = None
):
    query = db.query(AttackerProfile).filter(AttackerProfile.attack_count >= min_attacks)
    
    if is_blocked is not None:
        query = query.filter(AttackerProfile.is_blocked == is_blocked)
    
    attackers = query.order_by(AttackerProfile.attack_count.desc()).limit(limit).all()
    
    return [
        AttackerProfileResponse(
            id=attacker.id,
            ip_address=attacker.ip_address,
            first_seen=attacker.first_seen,
            last_seen=attacker.last_seen,
            attack_count=attacker.attack_count,
            country=attacker.country,
            asn=attacker.asn,
            organization=attacker.organization,
            threat_score=attacker.threat_score,
            is_blocked=attacker.is_blocked,
            behavior_patterns=attacker.behavior_patterns or {},
            attack_methods=attacker.attack_methods or [],
            last_attack_type=attacker.last_attack_type
        )
        for attacker in attackers
    ]

@router.get("/stats/summary")
async def get_attack_stats_summary(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    hours: int = Query(24, ge=1, le=720)
):
    time_threshold = datetime.utcnow() - timedelta(hours=hours)
    
    total_attacks = db.query(AttackEvent).filter(AttackEvent.timestamp >= time_threshold).count()
    unique_attackers = db.query(AttackEvent.source_ip).filter(AttackEvent.timestamp >= time_threshold).distinct().count()
    malicious_attacks = db.query(AttackEvent).filter(AttackEvent.timestamp >= time_threshold, AttackEvent.is_malicious == True).count()
    
    honeypot_stats = db.query(
        AttackEvent.honeypot_type,
        db.func.count(AttackEvent.id)
    ).filter(AttackEvent.timestamp >= time_threshold).group_by(AttackEvent.honeypot_type).all()
    
    threat_level_stats = db.query(
        AttackEvent.threat_level,
        db.func.count(AttackEvent.id)
    ).filter(AttackEvent.timestamp >= time_threshold).group_by(AttackEvent.threat_level).all()
    
    top_attackers = db.query(
        AttackEvent.source_ip,
        db.func.count(AttackEvent.id).label('attack_count')
    ).filter(AttackEvent.timestamp >= time_threshold).group_by(AttackEvent.source_ip).order_by(db.func.count(AttackEvent.id).desc()).limit(10).all()
    
    return {
        "timeframe_hours": hours,
        "total_attacks": total_attacks,
        "unique_attackers": unique_attackers,
        "malicious_attacks": malicious_attacks,
        "malicious_percentage": (malicious_attacks / total_attacks * 100) if total_attacks > 0 else 0,
        "honeypot_distribution": dict(honeypot_stats),
        "threat_level_distribution": dict(threat_level_stats),
        "top_attackers": [{"ip": ip, "count": count} for ip, count in top_attackers]
    }

@router.get("/analysis/patterns")
async def get_attack_patterns_analysis(
    current_user: dict = Depends(get_current_active_user),
    hours: int = Query(24, ge=1, le=168)
):
    analysis_result = await analyze_attack_patterns(hours)
    return analysis_result