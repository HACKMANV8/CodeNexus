"""
ML Background Worker
Processes ML predictions and model training in background
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import time

from app.core.database import get_db
from app.models.database_models import AttackEvent, MLPrediction
from app.ml.threat_classifier import ThreatClassifier
from app.ml.behavior_predictor import BehaviorPredictor
from app.ml.url_detector import URLDetector
from app.utils.logger import get_logger

logger = get_logger(__name__)

class MLWorker:
    def __init__(self):
        self.is_running = False
        self.processing_interval = 30
        self.batch_size = 100
        self.models_loaded = False
        self.threat_classifier = None
        self.behavior_predictor = None
        self.url_detector = None
        self._initialize_models()

    def _initialize_models(self):
        try:
            self.threat_classifier = ThreatClassifier()
            self.behavior_predictor = BehaviorPredictor()
            self.url_detector = URLDetector()
            
            self.models_loaded = True
            logger.info("ML models initialized for worker")
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
            self.models_loaded = False

    async def start(self):
        if self.is_running:
            logger.warning("ML worker already running")
            return

        self.is_running = True
        logger.info("Starting ML background worker")

        try:
            while self.is_running:
                start_time = time.time()
                
                try:
                    await self._process_pending_predictions()
                    await self._train_models_if_needed()
                    await self._update_model_performance()
                except Exception as e:
                    logger.error(f"ML worker processing error: {e}")

                processing_time = time.time() - start_time
                sleep_time = max(1, self.processing_interval - processing_time)
                
                await asyncio.sleep(sleep_time)

        except asyncio.CancelledError:
            logger.info("ML worker stopped")
        except Exception as e:
            logger.error(f"ML worker crashed: {e}")
        finally:
            self.is_running = False

    async def stop(self):
        self.is_running = False
        logger.info("Stopping ML worker")

    async def _process_pending_predictions(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            unprocessed_events = db.query(AttackEvent).filter(
                AttackEvent.ml_confidence.is_(None),
                AttackEvent.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).limit(self.batch_size).all()

            if not unprocessed_events:
                db.close()
                return

            logger.info(f"Processing {len(unprocessed_events)} events for ML predictions")

            for event in unprocessed_events:
                try:
                    prediction_result = await self._classify_attack_event(event)
                    
                    ml_prediction = MLPrediction(
                        event_id=event.event_id,
                        model_name="threat_classifier",
                        prediction=prediction_result.get('threat_level', 'low'),
                        confidence=prediction_result.get('confidence', 0.0),
                        features=prediction_result.get('features', {}),
                        timestamp=datetime.utcnow(),
                        model_version="1.0"
                    )
                    
                    db.add(ml_prediction)
                    
                    event.ml_confidence = prediction_result.get('confidence')
                    event.threat_level = prediction_result.get('threat_level')
                    event.is_malicious = prediction_result.get('threat_level') in ['high', 'critical']

                except Exception as e:
                    logger.error(f"Failed to process event {event.event_id}: {e}")
                    continue

            db.commit()
            logger.info(f"Completed ML predictions for {len(unprocessed_events)} events")
            db.close()

        except Exception as e:
            logger.error(f"Failed to process pending predictions: {e}")

    async def _classify_attack_event(self, attack_event: AttackEvent) -> Dict[str, Any]:
        try:
            if not self.models_loaded or not self.threat_classifier:
                return self._get_fallback_prediction(attack_event)

            event_data = {
                'honeypot_type': attack_event.honeypot_type,
                'source_ip': attack_event.source_ip,
                'payload': attack_event.payload,
                'user_agent': attack_event.user_agent,
                'country': attack_event.country,
                'timestamp': attack_event.timestamp
            }

            classification = self.threat_classifier.classify_threat_level(event_data)
            return classification

        except Exception as e:
            logger.error(f"Attack event classification failed: {e}")
            return self._get_fallback_prediction(attack_event)

    def _get_fallback_prediction(self, attack_event: AttackEvent) -> Dict[str, Any]:
        threat_level = 'medium' if attack_event.honeypot_type == 'ssh' else 'low'
        confidence = 0.5 if attack_event.honeypot_type == 'ssh' else 0.3
        
        return {
            'threat_level': threat_level,
            'confidence': confidence,
            'features': {},
            'fallback': True
        }

    async def _train_models_if_needed(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            recent_events_count = db.query(AttackEvent).filter(
                AttackEvent.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).count()

            if recent_events_count >= 1000:
                logger.info("Sufficient data available for model retraining")
                
            db.close()

        except Exception as e:
            logger.error(f"Model training check failed: {e}")

    async def _update_model_performance(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            recent_predictions = db.query(MLPrediction).filter(
                MLPrediction.timestamp >= datetime.utcnow() - timedelta(hours=1)
            ).all()

            if recent_predictions:
                avg_confidence = sum(p.confidence for p in recent_predictions) / len(recent_predictions)
                logger.debug(f"Average ML prediction confidence: {avg_confidence:.3f}")

            db.close()

        except Exception as e:
            logger.error(f"Model performance update failed: {e}")

    async def process_single_event(self, event_id: str) -> bool:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            event = db.query(AttackEvent).filter(AttackEvent.event_id == event_id).first()
            if not event:
                logger.warning(f"Event {event_id} not found for ML processing")
                db.close()
                return False

            prediction_result = await self._classify_attack_event(event)
            
            ml_prediction = MLPrediction(
                event_id=event.event_id,
                model_name="threat_classifier",
                prediction=prediction_result.get('threat_level', 'low'),
                confidence=prediction_result.get('confidence', 0.0),
                features=prediction_result.get('features', {}),
                timestamp=datetime.utcnow(),
                model_version="1.0"
            )
            
            db.add(ml_prediction)
            event.ml_confidence = prediction_result.get('confidence')
            event.threat_level = prediction_result.get('threat_level')
            event.is_malicious = prediction_result.get('threat_level') in ['high', 'critical']
            
            db.commit()
            db.close()
            
            logger.info(f"Processed single event {event_id} with ML")
            return True

        except Exception as e:
            logger.error(f"Failed to process single event {event_id}: {e}")
            return False

    def get_worker_status(self) -> Dict[str, Any]:
        return {
            'is_running': self.is_running,
            'models_loaded': self.models_loaded,
            'processing_interval': self.processing_interval,
            'batch_size': self.batch_size,
            'last_activity': datetime.utcnow().isoformat()
        }

ml_worker = MLWorker()

async def start_ml_worker():
    worker = MLWorker()
    await worker.start()
    return worker

async def process_ml_predictions():
    worker = MLWorker()
    await worker._process_pending_predictions()