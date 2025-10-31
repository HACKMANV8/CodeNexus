"""
Response Actions API Endpoints
Attack response management and automation
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.database_models import ResponseAction, AttackEvent
from app.models.schemas import ResponseActionCreate, ResponseActionResponse
from app.pipeline.responder import ResponseEngine

router = APIRouter()

@router.get("/", response_model=List[ResponseActionResponse])
async def get_response_actions(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    status: Optional[str] = None,
    action_type: Optional[str] = None,
    limit: int = 100
):
    query = db.query(ResponseAction)
    
    if status:
        query = query.filter(ResponseAction.status == status)
    
    if action_type:
        query = query.filter(ResponseAction.action_type == action_type)
    
    actions = query.order_by(ResponseAction.created_at.desc()).limit(limit).all()
    
    return [
        ResponseActionResponse(
            id=action.id,
            action_id=action.action_id,
            event_id=action.event_id,
            attacker_ip=action.attacker_ip,
            action_type=action.action_type,
            action_details=action.action_details or {},
            status=action.status,
            created_by=action.created_by,
            created_at=action.created_at,
            executed_at=action.executed_at,
            ttl=action.ttl
        )
        for action in actions
    ]

@router.post("/", response_model=ResponseActionResponse)
async def create_response_action(
    response_data: ResponseActionCreate,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    existing_event = db.query(AttackEvent).filter(AttackEvent.event_id == response_data.event_id).first()
    
    if not existing_event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack event not found"
        )
    
    response_engine = ResponseEngine()
    
    execution_result = await response_engine.execute_response_action(
        response_data,
        approved_by=current_user["username"]
    )
    
    if not execution_result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute response action"
        )
    
    recent_action = db.query(ResponseAction).filter(
        ResponseAction.event_id == response_data.event_id
    ).order_by(ResponseAction.created_at.desc()).first()
    
    if not recent_action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Response action not found after creation"
        )
    
    return ResponseActionResponse(
        id=recent_action.id,
        action_id=recent_action.action_id,
        event_id=recent_action.event_id,
        attacker_ip=recent_action.attacker_ip,
        action_type=recent_action.action_type,
        action_details=recent_action.action_details or {},
        status=recent_action.status,
        created_by=recent_action.created_by,
        created_at=recent_action.created_at,
        executed_at=recent_action.executed_at,
        ttl=recent_action.ttl
    )

@router.get("/pending", response_model=List[ResponseActionResponse])
async def get_pending_actions(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    pending_actions = db.query(ResponseAction).filter(
        ResponseAction.status == "pending_approval"
    ).order_by(ResponseAction.created_at.desc()).all()
    
    return [
        ResponseActionResponse(
            id=action.id,
            action_id=action.action_id,
            event_id=action.event_id,
            attacker_ip=action.attacker_ip,
            action_type=action.action_type,
            action_details=action.action_details or {},
            status=action.status,
            created_by=action.created_by,
            created_at=action.created_at,
            executed_at=action.executed_at,
            ttl=action.ttl
        )
        for action in pending_actions
    ]

@router.post("/{action_id}/approve")
async def approve_response_action(
    action_id: str,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    action = db.query(ResponseAction).filter(ResponseAction.action_id == action_id).first()
    
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Response action not found"
        )
    
    if action.status != "pending_approval":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Action is not pending approval"
        )
    
    response_engine = ResponseEngine()
    
    from app.models.schemas import ResponseActionCreate
    action_data = ResponseActionCreate(
        event_id=action.event_id,
        attacker_ip=action.attacker_ip,
        action_type=action.action_type,
        action_details=action.action_details or {},
        ttl=action.ttl
    )
    
    execution_result = await response_engine.execute_response_action(
        action_data,
        approved_by=current_user["username"]
    )
    
    if execution_result:
        action.status = "executed"
        action.executed_at = db.query(ResponseAction).filter(ResponseAction.action_id == action_id).first().executed_at
        action.created_by = current_user["username"]
        db.commit()
        
        return {"message": "Response action approved and executed successfully"}
    else:
        action.status = "failed"
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute approved response action"
        )

@router.post("/{action_id}/reject")
async def reject_response_action(
    action_id: str,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    action = db.query(ResponseAction).filter(ResponseAction.action_id == action_id).first()
    
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Response action not found"
        )
    
    if action.status != "pending_approval":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Action is not pending approval"
        )
    
    action.status = "rejected"
    action.created_by = current_user["username"]
    db.commit()
    
    return {"message": "Response action rejected successfully"}

@router.get("/stats")
async def get_response_stats(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    hours: int = 24
):
    from datetime import datetime, timedelta
    
    time_threshold = datetime.utcnow() - timedelta(hours=hours)
    
    total_actions = db.query(ResponseAction).filter(ResponseAction.created_at >= time_threshold).count()
    
    status_counts = db.query(
        ResponseAction.status,
        db.func.count(ResponseAction.id)
    ).filter(ResponseAction.created_at >= time_threshold).group_by(ResponseAction.status).all()
    
    type_counts = db.query(
        ResponseAction.action_type,
        db.func.count(ResponseAction.id)
    ).filter(ResponseAction.created_at >= time_threshold).group_by(ResponseAction.action_type).all()
    
    automated_count = db.query(ResponseAction).filter(
        ResponseAction.created_at >= time_threshold,
        ResponseAction.created_by == "system"
    ).count()
    
    manual_count = total_actions - automated_count
    
    return {
        "timeframe_hours": hours,
        "total_actions": total_actions,
        "status_breakdown": dict(status_counts),
        "type_breakdown": dict(type_counts),
        "automation_stats": {
            "automated": automated_count,
            "manual": manual_count,
            "automation_rate": (automated_count / total_actions * 100) if total_actions > 0 else 0
        }
    }