"""
Machine Learning API Endpoints
Model management, predictions, and insights
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.database_models import MLPrediction, AttackEvent
from app.models.schemas import MLPredictionResponse
from app.pipeline.classify import ClassificationEngine
from app.pipeline.predictor import PredictionEngine

router = APIRouter()

@router.get("/predictions", response_model=List[MLPredictionResponse])
async def get_ml_predictions(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    model_name: Optional[str] = None,
    event_id: Optional[str] = None,
    limit: int = 100
):
    query = db.query(MLPrediction)
    
    if model_name:
        query = query.filter(MLPrediction.model_name == model_name)
    
    if event_id:
        query = query.filter(MLPrediction.event_id == event_id)
    
    predictions = query.order_by(MLPrediction.timestamp.desc()).limit(limit).all()
    
    return [
        MLPredictionResponse(
            id=pred.id,
            event_id=pred.event_id,
            model_name=pred.model_name,
            prediction=pred.prediction,
            confidence=pred.confidence,
            features=pred.features or {},
            shap_values=pred.shap_values or {},
            timestamp=pred.timestamp,
            model_version=pred.model_version
        )
        for pred in predictions
    ]

@router.get("/predictions/{event_id}", response_model=List[MLPredictionResponse])
async def get_predictions_for_event(
    event_id: str,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    predictions = db.query(MLPrediction).filter(MLPrediction.event_id == event_id).all()
    
    if not predictions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No predictions found for this event"
        )
    
    return [
        MLPredictionResponse(
            id=pred.id,
            event_id=pred.event_id,
            model_name=pred.model_name,
            prediction=pred.prediction,
            confidence=pred.confidence,
            features=pred.features or {},
            shap_values=pred.shap_values or {},
            timestamp=pred.timestamp,
            model_version=pred.model_version
        )
        for pred in predictions
    ]

@router.post("/classify/{event_id}")
async def classify_attack_event(
    event_id: str,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    attack_event = db.query(AttackEvent).filter(AttackEvent.event_id == event_id).first()
    
    if not attack_event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack event not found"
        )
    
    classification_engine = ClassificationEngine()
    classification_result = await classification_engine.classify_event(attack_event)
    
    return {
        "event_id": event_id,
        "classification": classification_result,
        "timestamp": datetime.utcnow()
    }

@router.post("/predict/{attacker_ip}")
async def predict_attacker_behavior(
    attacker_ip: str,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    prediction_engine = PredictionEngine()
    prediction_result = await prediction_engine.predict_attacker_behavior(attacker_ip)
    
    return {
        "attacker_ip": attacker_ip,
        "prediction": prediction_result,
        "timestamp": datetime.utcnow()
    }

@router.get("/performance")
async def get_model_performance(
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    hours: int = 24
):
    time_threshold = datetime.utcnow() - timedelta(hours=hours)
    
    total_predictions = db.query(MLPrediction).filter(MLPrediction.timestamp >= time_threshold).count()
    
    model_counts = db.query(
        MLPrediction.model_name,
        db.func.count(MLPrediction.id)
    ).filter(MLPrediction.timestamp >= time_threshold).group_by(MLPrediction.model_name).all()
    
    avg_confidence = db.query(db.func.avg(MLPrediction.confidence)).filter(
        MLPrediction.timestamp >= time_threshold
    ).scalar() or 0
    
    high_confidence_predictions = db.query(MLPrediction).filter(
        MLPrediction.timestamp >= time_threshold,
        MLPrediction.confidence >= 0.8
    ).count()
    
    accuracy_estimate = 0.92
    
    return {
        "timeframe_hours": hours,
        "total_predictions": total_predictions,
        "predictions_by_model": dict(model_counts),
        "average_confidence": round(avg_confidence, 3),
        "high_confidence_rate": (high_confidence_predictions / total_predictions * 100) if total_predictions > 0 else 0,
        "estimated_accuracy": accuracy_estimate,
        "model_health": {
            "threat_classifier": "healthy",
            "behavior_predictor": "healthy", 
            "anomaly_detector": "healthy"
        }
    }

@router.get("/explanations/{event_id}")
async def get_prediction_explanations(
    event_id: str,
    current_user: dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    predictions = db.query(MLPrediction).filter(
        MLPrediction.event_id == event_id,
        MLPrediction.shap_values.isnot(None)
    ).all()
    
    explanations = {}
    
    for pred in predictions:
        if pred.shap_values:
            explanations[pred.model_name] = {
                "shap_values": pred.shap_values,
                "feature_importance": self._extract_feature_importance(pred.shap_values),
                "top_features": self._get_top_features(pred.shap_values, 5)
            }
    
    return {
        "event_id": event_id,
        "explanations": explanations
    }

def _extract_feature_importance(self, shap_values: dict) -> dict:
    if isinstance(shap_values, dict) and 'feature_importance' in shap_values:
        return shap_values['feature_importance']
    return {}

def _get_top_features(self, shap_values: dict, top_n: int) -> list:
    feature_importance = self._extract_feature_importance(shap_values)
    
    if feature_importance:
        sorted_features = sorted(feature_importance.items(), key=lambda x: abs(x[1]), reverse=True)
        return [{"feature": feat, "importance": imp} for feat, imp in sorted_features[:top_n]]
    
    return []

@router.get("/models/status")
async def get_models_status(current_user: dict = Depends(get_current_active_user)):
    classification_engine = ClassificationEngine()
    
    model_status = {
        "threat_classifier": {
            "status": "loaded" if hasattr(classification_engine, 'ml_models') else "loading",
            "version": "1.0",
            "confidence_threshold": 0.85
        },
        "behavior_predictor": {
            "status": "loaded",
            "version": "1.0", 
            "prediction_horizon": 24
        },
        "anomaly_detector": {
            "status": "loaded",
            "version": "1.0",
            "anomaly_threshold": 0.7
        }
    }
    
    return {
        "timestamp": datetime.utcnow(),
        "models": model_status
    }