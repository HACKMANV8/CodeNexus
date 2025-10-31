"""
Threat Intelligence API Endpoints
IOC management and threat data
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.database_models import ThreatIntelligence, AttackEvent
from app.models.schemas import ThreatIntelCreate, ThreatIntelResponse

router = APIRouter()

@router.get("/iocs", response_model=List[ThreatIntelResponse])
async def get_threat_intelligence(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    ioc_type: Optional[str] = None,
    source: Optional[str] = None,
    active_only: bool = True,
    limit: int = 100
):
    query = db.query(ThreatIntelligence)
    
    if ioc_type:
        query = query.filter(ThreatIntelligence.ioc_type == ioc_type)
    
    if source:
        query = query.filter(ThreatIntelligence.source == source)
    
    if active_only:
        query = query.filter(ThreatIntelligence.is_active == True)
    
    iocs = query.order_by(ThreatIntelligence.last_seen.desc()).limit(limit).all()
    
    return [
        ThreatIntelResponse(
            id=ioc.id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.ioc_value,
            source=ioc.source,
            confidence=ioc.confidence,
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen,
            tags=ioc.tags or {},
            description=ioc.description,
            is_active=ioc.is_active
        )
        for ioc in iocs
    ]

@router.post("/iocs", response_model=ThreatIntelResponse)
async def create_threat_intel(
    ioc_data: ThreatIntelCreate,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    existing_ioc = db.query(ThreatIntelligence).filter(
        ThreatIntelligence.ioc_type == ioc_data.ioc_type,
        ThreatIntelligence.ioc_value == ioc_data.ioc_value
    ).first()
    
    if existing_ioc:
        existing_ioc.last_seen = db.query(ThreatIntelligence).filter(ThreatIntelligence.id == existing_ioc.id).first().last_seen
        existing_ioc.confidence = max(existing_ioc.confidence, ioc_data.confidence)
        
        if ioc_data.tags:
            existing_tags = existing_ioc.tags or {}
            existing_tags.update(ioc_data.tags)
            existing_ioc.tags = existing_tags
        
        db.commit()
        db.refresh(existing_ioc)
        
        return ThreatIntelResponse(
            id=existing_ioc.id,
            ioc_type=existing_ioc.ioc_type,
            ioc_value=existing_ioc.ioc_value,
            source=existing_ioc.source,
            confidence=existing_ioc.confidence,
            first_seen=existing_ioc.first_seen,
            last_seen=existing_ioc.last_seen,
            tags=existing_ioc.tags or {},
            description=existing_ioc.description,
            is_active=existing_ioc.is_active
        )
    
    new_ioc = ThreatIntelligence(
        ioc_type=ioc_data.ioc_type,
        ioc_value=ioc_data.ioc_value,
        source=ioc_data.source,
        confidence=ioc_data.confidence,
        tags=ioc_data.tags,
        description=ioc_data.description
    )
    
    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)
    
    return ThreatIntelResponse(
        id=new_ioc.id,
        ioc_type=new_ioc.ioc_type,
        ioc_value=new_ioc.ioc_value,
        source=new_ioc.source,
        confidence=new_ioc.confidence,
        first_seen=new_ioc.first_seen,
        last_seen=new_ioc.last_seen,
        tags=new_ioc.tags or {},
        description=new_ioc.description,
        is_active=new_ioc.is_active
    )

@router.get("/iocs/stats")
async def get_threat_intel_stats(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    total_iocs = db.query(ThreatIntelligence).count()
    active_iocs = db.query(ThreatIntelligence).filter(ThreatIntelligence.is_active == True).count()
    
    iocs_by_type = db.query(
        ThreatIntelligence.ioc_type,
        db.func.count(ThreatIntelligence.id)
    ).group_by(ThreatIntelligence.ioc_type).all()
    
    iocs_by_source = db.query(
        ThreatIntelligence.source,
        db.func.count(ThreatIntelligence.id)
    ).group_by(ThreatIntelligence.source).all()
    
    avg_confidence = db.query(db.func.avg(ThreatIntelligence.confidence)).scalar() or 0
    
    recent_iocs = db.query(ThreatIntelligence).filter(
        ThreatIntelligence.is_active == True
    ).order_by(ThreatIntelligence.last_seen.desc()).limit(10).all()
    
    return {
        "total_iocs": total_iocs,
        "active_iocs": active_iocs,
        "iocs_by_type": dict(iocs_by_type),
        "iocs_by_source": dict(iocs_by_source),
        "average_confidence": round(avg_confidence, 3),
        "recent_iocs": [
            {
                "ioc_type": ioc.ioc_type,
                "ioc_value": ioc.ioc_value,
                "source": ioc.source,
                "last_seen": ioc.last_seen
            }
            for ioc in recent_iocs
        ]
    }

@router.get("/iocs/check")
async def check_ioc(
    ioc_type: str,
    ioc_value: str,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    ioc = db.query(ThreatIntelligence).filter(
        ThreatIntelligence.ioc_type == ioc_type,
        ThreatIntelligence.ioc_value == ioc_value,
        ThreatIntelligence.is_active == True
    ).first()
    
    if ioc:
        return {
            "found": True,
            "ioc": {
                "ioc_type": ioc.ioc_type,
                "ioc_value": ioc.ioc_value,
                "source": ioc.source,
                "confidence": ioc.confidence,
                "first_seen": ioc.first_seen,
                "last_seen": ioc.last_seen,
                "tags": ioc.tags or {}
            }
        }
    else:
        return {"found": False}

@router.get("/correlation/{attacker_ip}")
async def get_attacker_correlation(
    attacker_ip: str,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    attacks = db.query(AttackEvent).filter(AttackEvent.source_ip == attacker_ip).all()
    
    if not attacks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No attacks found for this IP"
        )
    
    attack_count = len(attacks)
    first_seen = min(attack.timestamp for attack in attacks)
    last_seen = max(attack.timestamp for attack in attacks)
    
    honeypot_types = list(set(attack.honeypot_type for attack in attacks))
    countries = list(set(attack.country for attack in attacks if attack.country))
    
    threat_levels = [attack.threat_level for attack in attacks]
    most_common_threat = max(set(threat_levels), key=threat_levels.count)
    
    malicious_count = sum(1 for attack in attacks if attack.is_malicious)
    
    ioc_matches = db.query(ThreatIntelligence).filter(
        ThreatIntelligence.ioc_type == "ip_address",
        ThreatIntelligence.ioc_value == attacker_ip,
        ThreatIntelligence.is_active == True
    ).all()
    
    return {
        "attacker_ip": attacker_ip,
        "attack_stats": {
            "total_attacks": attack_count,
            "malicious_attacks": malicious_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "honeypot_types": honeypot_types,
            "countries": countries,
            "most_common_threat": most_common_threat
        },
        "ioc_matches": [
            {
                "source": ioc.source,
                "confidence": ioc.confidence,
                "first_seen": ioc.first_seen,
                "tags": ioc.tags or {}
            }
            for ioc in ioc_matches
        ],
        "threat_assessment": {
            "risk_level": "high" if malicious_count > 5 else "medium" if malicious_count > 0 else "low",
            "confidence": min(malicious_count / attack_count * 100, 100) if attack_count > 0 else 0
        }
    }

@router.delete("/iocs/{ioc_id}")
async def deactivate_ioc(
    ioc_id: int,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    ioc = db.query(ThreatIntelligence).filter(ThreatIntelligence.id == ioc_id).first()
    
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found"
        )
    
    ioc.is_active = False
    db.commit()
    
    return {"message": "IOC deactivated successfully"}