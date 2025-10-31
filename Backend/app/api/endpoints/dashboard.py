"""
Dashboard API Endpoints
Real-time metrics and system overview
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.database_models import AttackEvent, AttackerProfile, MLPrediction
from app.honeypots.factory import HoneypotFactory

router = APIRouter()

@router.get("/overview")
async def get_dashboard_overview(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    now = datetime.utcnow()
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)
    
    attacks_last_hour = db.query(AttackEvent).filter(AttackEvent.timestamp >= hour_ago).count()
    attacks_last_day = db.query(AttackEvent).filter(AttackEvent.timestamp >= day_ago).count()
    attacks_last_week = db.query(AttackEvent).filter(AttackEvent.timestamp >= week_ago).count()
    
    unique_attackers_last_day = db.query(AttackEvent.source_ip).filter(AttackEvent.timestamp >= day_ago).distinct().count()
    
    high_severity_attacks = db.query(AttackEvent).filter(
        AttackEvent.timestamp >= day_ago,
        AttackEvent.threat_level.in_(["high", "critical"])
    ).count()
    
    ml_predictions_count = db.query(MLPrediction).filter(MLPrediction.timestamp >= day_ago).count()
    ml_accuracy = 0.95
    
    honeypot_factory = HoneypotFactory()
    honeypot_stats = honeypot_factory.get_honeypot_stats()
    
    active_honeypots = sum(1 for stats in honeypot_stats.values() if stats["is_running"])
    
    return {
        "timestamp": now,
        "attack_metrics": {
            "last_hour": attacks_last_hour,
            "last_24_hours": attacks_last_day,
            "last_7_days": attacks_last_week,
            "unique_attackers_24h": unique_attackers_last_day,
            "high_severity_24h": high_severity_attacks
        },
        "system_metrics": {
            "active_honeypots": active_honeypots,
            "total_honeypots": len(honeypot_stats),
            "ml_predictions_24h": ml_predictions_count,
            "ml_accuracy": ml_accuracy
        },
        "honeypot_status": honeypot_stats
    }

@router.get("/metrics/realtime")
async def get_realtime_metrics(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    now = datetime.utcnow()
    minute_ago = now - timedelta(minutes=1)
    ten_minutes_ago = now - timedelta(minutes=10)
    
    current_attacks = db.query(AttackEvent).filter(AttackEvent.timestamp >= minute_ago).count()
    attacks_10min = db.query(AttackEvent).filter(AttackEvent.timestamp >= ten_minutes_ago).count()
    
    attack_trend = "increasing" if current_attacks > (attacks_10min / 10) else "decreasing"
    
    top_attack_types = db.query(
        AttackEvent.honeypot_type,
        db.func.count(AttackEvent.id)
    ).filter(AttackEvent.timestamp >= ten_minutes_ago).group_by(AttackEvent.honeypot_type).order_by(db.func.count(AttackEvent.id).desc()).limit(5).all()
    
    recent_malicious = db.query(AttackEvent).filter(
        AttackEvent.timestamp >= ten_minutes_ago,
        AttackEvent.is_malicious == True
    ).order_by(AttackEvent.timestamp.desc()).limit(5).all()
    
    return {
        "timestamp": now,
        "current_attack_rate": current_attacks,
        "attack_trend": attack_trend,
        "top_attack_types": dict(top_attack_types),
        "recent_malicious_attacks": [
            {
                "source_ip": attack.source_ip,
                "honeypot_type": attack.honeypot_type,
                "threat_level": attack.threat_level,
                "timestamp": attack.timestamp
            }
            for attack in recent_malicious
        ]
    }

@router.get("/geodata")
async def get_attack_geodata(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    hours: int = 24
):
    time_threshold = datetime.utcnow() - timedelta(hours=hours)
    
    geo_data = db.query(
        AttackEvent.country,
        AttackEvent.city,
        AttackEvent.latitude,
        AttackEvent.longitude,
        db.func.count(AttackEvent.id).label('attack_count')
    ).filter(
        AttackEvent.timestamp >= time_threshold,
        AttackEvent.country.isnot(None),
        AttackEvent.latitude.isnot(None),
        AttackEvent.longitude.isnot(None)
    ).group_by(
        AttackEvent.country,
        AttackEvent.city,
        AttackEvent.latitude,
        AttackEvent.longitude
    ).all()
    
    country_stats = db.query(
        AttackEvent.country,
        db.func.count(AttackEvent.id).label('attack_count')
    ).filter(
        AttackEvent.timestamp >= time_threshold,
        AttackEvent.country.isnot(None)
    ).group_by(AttackEvent.country).all()
    
    return {
        "timeframe_hours": hours,
        "attack_locations": [
            {
                "country": country,
                "city": city,
                "latitude": lat,
                "longitude": lng,
                "attack_count": count
            }
            for country, city, lat, lng, count in geo_data
        ],
        "country_stats": [
            {
                "country": country,
                "attack_count": count
            }
            for country, count in country_stats
        ]
    }

@router.get("/honeypots/status")
async def get_honeypots_status(current_user: dict = Depends(get_current_active_user)):
    factory = HoneypotFactory()
    status = await factory.health_check()
    detailed_stats = factory.get_detailed_stats()
    
    return {
        "status": status,
        "detailed_stats": detailed_stats
    }

@router.get("/system/health")
async def get_system_health(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    from app.core.database import check_db_health
    from app.core.cache import cache_manager
    
    db_health = check_db_health()
    cache_health = cache_manager.get_stats()
    
    honeypot_factory = HoneypotFactory()
    honeypot_health = await honeypot_factory.health_check()
    
    all_healthy = db_health and cache_health.get("type") != "error"
    
    return {
        "status": "healthy" if all_healthy else "degraded",
        "timestamp": datetime.utcnow(),
        "components": {
            "database": "healthy" if db_health else "unhealthy",
            "cache": cache_health.get("type", "unknown"),
            "honeypots": honeypot_health
        },
        "metrics": {
            "database_connections": 0,
            "cache_hit_rate": 0,
            "active_honeypots": len([h for h in honeypot_health.values() if h.get("status") == "healthy"])
        }
    }