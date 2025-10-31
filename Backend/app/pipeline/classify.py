"""
Attack Classification Pipeline
Uses ML models to classify and score attack events
"""

import logging
from typing import Dict, Any, Optional
import numpy as np
from datetime import datetime

from app.models.database_models import AttackEvent, MLPrediction
from app.models.ml_models import ModelPrediction, MLFeatureSet
from app.core.database import get_db
from app.core.config import settings

logger = logging.getLogger(__name__)

class ClassificationEngine:
    def __init__(self):
        self.ml_models = {}
        self.confidence_threshold = settings.ml_confidence_threshold
        self._load_models()

    def _load_models(self):
        try:
            self.ml_models["threat_classifier"] = self._load_threat_classifier()
            self.ml_models["anomaly_detector"] = self._load_anomaly_detector()
            logger.info("ML models loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load ML models: {e}")

    def _load_threat_classifier(self):
        return {"name": "threat_classifier", "version": "1.0"}

    def _load_anomaly_detector(self):
        return {"name": "anomaly_detector", "version": "1.0"}

    async def classify_event(self, attack_event: AttackEvent) -> Dict[str, Any]:
        classification_result = {
            "is_malicious": False,
            "confidence": 0.0,
            "threat_level": "low",
            "model_predictions": []
        }

        try:
            features = await self._extract_features(attack_event)
            
            threat_prediction = await self._predict_threat_level(features)
            anomaly_score = await self._calculate_anomaly_score(features)
            
            classification_result["model_predictions"].append(threat_prediction)
            classification_result["model_predictions"].append(anomaly_score)
            
            final_prediction = self._combine_predictions(classification_result["model_predictions"])
            
            classification_result.update(final_prediction)
            
            await self._store_prediction(attack_event, classification_result, features)
            
        except Exception as e:
            logger.error(f"Classification failed: {e}")

        return classification_result

    async def _extract_features(self, attack_event: AttackEvent) -> Dict[str, Any]:
        features = {
            "source_ip_unique": self._ip_to_numeric(attack_event.source_ip),
            "payload_length": len(attack_event.payload) if attack_event.payload else 0,
            "has_suspicious_user_agent": self._check_suspicious_user_agent(attack_event.user_agent),
            "is_known_malicious_country": self._check_malicious_country(attack_event.country),
            "attack_frequency": await self._get_attack_frequency(attack_event.source_ip)
        }
        
        return features

    async def _predict_threat_level(self, features: Dict[str, Any]) -> ModelPrediction:
        feature_vector = list(features.values())
        
        mock_confidence = self._mock_ml_prediction(feature_vector)
        
        prediction = "malicious" if mock_confidence > self.confidence_threshold else "benign"
        
        return ModelPrediction(
            prediction_id=f"pred_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            model_type="threat_classifier",
            input_features=features,
            output_prediction=prediction,
            confidence=mock_confidence,
            probabilities={"malicious": mock_confidence, "benign": 1 - mock_confidence},
            timestamp=datetime.utcnow(),
            model_version="1.0"
        )

    async def _calculate_anomaly_score(self, features: Dict[str, Any]) -> ModelPrediction:
        feature_vector = list(features.values())
        anomaly_score = sum(feature_vector) / len(feature_vector) if feature_vector else 0
        
        return ModelPrediction(
            prediction_id=f"anomaly_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            model_type="anomaly_detector",
            input_features=features,
            output_prediction="anomalous" if anomaly_score > 0.7 else "normal",
            confidence=anomaly_score,
            probabilities={"anomalous": anomaly_score, "normal": 1 - anomaly_score},
            timestamp=datetime.utcnow(),
            model_version="1.0"
        )

    def _combine_predictions(self, predictions: list) -> Dict[str, Any]:
        threat_pred = next(p for p in predictions if p.model_type == "threat_classifier")
        anomaly_pred = next(p for p in predictions if p.model_type == "anomaly_detector")
        
        combined_confidence = (threat_pred.confidence + anomaly_pred.confidence) / 2
        is_malicious = threat_pred.output_prediction == "malicious" or anomaly_pred.output_prediction == "anomalous"
        
        threat_level = "critical" if combined_confidence > 0.9 else \
                      "high" if combined_confidence > 0.7 else \
                      "medium" if combined_confidence > 0.5 else "low"
        
        return {
            "is_malicious": is_malicious,
            "confidence": combined_confidence,
            "threat_level": threat_level
        }

    async def _store_prediction(self, attack_event: AttackEvent, classification: Dict[str, Any], features: Dict[str, Any]):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            ml_prediction = MLPrediction(
                event_id=attack_event.event_id,
                model_name="threat_classifier",
                prediction=classification["threat_level"],
                confidence=classification["confidence"],
                features=features,
                timestamp=datetime.utcnow(),
                model_version="1.0"
            )
            
            db.add(ml_prediction)
            
            attack_event.is_malicious = classification["is_malicious"]
            attack_event.ml_confidence = classification["confidence"]
            attack_event.threat_level = classification["threat_level"]
            
            db.commit()
            logger.info(f"Stored ML prediction for event {attack_event.event_id}")
            
        except Exception as e:
            logger.error(f"Failed to store ML prediction: {e}")
        finally:
            db.close()

    def _ip_to_numeric(self, ip_address: str) -> float:
        parts = ip_address.split('.')
        return sum(int(part) * (256 ** (3 - i)) for i, part in enumerate(parts)) / (256 ** 4)

    def _check_suspicious_user_agent(self, user_agent: Optional[str]) -> float:
        if not user_agent:
            return 0.0
            
        suspicious_indicators = ["nmap", "sqlmap", "metasploit", "hydra", "nikto"]
        return 1.0 if any(indicator in user_agent.lower() for indicator in suspicious_indicators) else 0.0

    def _check_malicious_country(self, country: Optional[str]) -> float:
        high_risk_countries = ["CN", "RU", "KP", "IR"]
        return 1.0 if country in high_risk_countries else 0.0

    async def _get_attack_frequency(self, ip_address: str) -> float:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            from sqlalchemy import func
            from datetime import datetime, timedelta
            
            hour_ago = datetime.utcnow() - timedelta(hours=1)
            attack_count = db.query(AttackEvent).filter(
                AttackEvent.source_ip == ip_address,
                AttackEvent.timestamp >= hour_ago
            ).count()
            
            return min(attack_count / 10.0, 1.0)
            
        except Exception as e:
            logger.debug(f"Failed to get attack frequency: {e}")
            return 0.0
        finally:
            db.close()

    def _mock_ml_prediction(self, features: list) -> float:
        return min(sum(features) / len(features) if features else 0, 1.0)

async def classify_attack(attack_event: AttackEvent) -> Dict[str, Any]:
    engine = ClassificationEngine()
    return await engine.classify_event(attack_event)