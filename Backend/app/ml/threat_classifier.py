"""
Threat Classification ML Model
Classifies attack events by threat level and type
"""

import logging
import numpy as np
from typing import Dict, Any, List, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder

from app.ml.base_model import BaseMLModel, ModelType
from app.ml.feature_engineer import FeatureEngineer

logger = logging.getLogger(__name__)

class ThreatClassifier(BaseMLModel):
    def __init__(self, version: str = "1.0"):
        super().__init__(ModelType.THREAT_CLASSIFIER, version)
        self.feature_engineer = FeatureEngineer()
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.threat_levels = ['low', 'medium', 'high', 'critical']
        self._initialize_model()

    def _initialize_model(self):
        try:
            self.model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            )
            logger.info("Threat classifier model initialized")
        except Exception as e:
            logger.error(f"Failed to initialize threat classifier: {e}")
            self.model = None

    def preprocess_data(self, attack_events: List[Dict[str, Any]]) -> np.ndarray:
        features = []
        
        for event in attack_events:
            event_features = self.feature_engineer.extract_threat_features(event)
            feature_vector = list(event_features.values())
            features.append(feature_vector)
        
        self.feature_names = list(event_features.keys()) if attack_events else []
        
        features_array = np.array(features)
        
        if hasattr(self, 'is_fitted') and self.is_fitted:
            features_array = self.scaler.transform(features_array)
        else:
            features_array = self.scaler.fit_transform(features_array)
            self.is_fitted = True
        
        return features_array

    def train(self, X, y, **kwargs) -> Dict[str, Any]:
        try:
            if self.model is None:
                self._initialize_model()
            
            X_processed = self.preprocess_data(X)
            y_encoded = self.label_encoder.fit_transform(y)
            
            self.model.fit(X_processed, y_encoded)
            self.is_trained = True
            self.metadata['last_trained'] = datetime.utcnow().isoformat()
            self.metadata['training_samples'] = len(X)
            self.metadata['feature_count'] = X_processed.shape[1]
            self.metadata['class_distribution'] = dict(zip(*np.unique(y, return_counts=True)))
            
            training_metrics = self.evaluate(X_processed, y_encoded)
            
            logger.info(f"Threat classifier trained on {len(X)} samples")
            return training_metrics
            
        except Exception as e:
            logger.error(f"Threat classifier training failed: {e}")
            return {}

    def predict(self, attack_events: List[Dict[str, Any]]) -> np.ndarray:
        if not self.validate_input(attack_events):
            return np.array([])
        
        try:
            X_processed = self.preprocess_data(attack_events)
            predictions_encoded = self.model.predict(X_processed)
            predictions = self.label_encoder.inverse_transform(predictions_encoded)
            return predictions
            
        except Exception as e:
            logger.error(f"Threat classification prediction failed: {e}")
            return np.array([])

    def predict_proba(self, attack_events: List[Dict[str, Any]]) -> np.ndarray:
        if not self.validate_input(attack_events):
            return np.array([])
        
        try:
            X_processed = self.preprocess_data(attack_events)
            probabilities = self.model.predict_proba(X_processed)
            return probabilities
            
        except Exception as e:
            logger.error(f"Threat classification probability prediction failed: {e}")
            return np.array([])

    def classify_threat_level(self, attack_event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            prediction = self.predict([attack_event])
            probability = self.predict_proba([attack_event])
            
            threat_level = prediction[0] if len(prediction) > 0 else 'low'
            confidence = float(np.max(probability[0])) if len(probability) > 0 else 0.0
            
            features = self.feature_engineer.extract_threat_features(attack_event)
            threat_indicators = self._identify_threat_indicators(attack_event, features)
            risk_score = self._calculate_risk_score(features, threat_level)
            
            return {
                'threat_level': threat_level,
                'confidence': confidence,
                'risk_score': risk_score,
                'threat_indicators': threat_indicators,
                'features': features,
                'probability_distribution': self._get_probability_distribution(probability[0]) if len(probability) > 0 else {}
            }
            
        except Exception as e:
            logger.error(f"Threat classification failed: {e}")
            return self._fallback_classification(attack_event)

    def _identify_threat_indicators(self, attack_event: Dict[str, Any], features: Dict[str, Any]) -> List[str]:
        indicators = []
        
        if features.get('payload_length', 0) > 1000:
            indicators.append('large_payload')
        
        if features.get('suspicious_user_agent', 0) == 1:
            indicators.append('suspicious_user_agent')
        
        if features.get('unusual_working_hours', 0) == 1:
            indicators.append('unusual_timing')
        
        if features.get('geo_risk_score', 0) > 0.7:
            indicators.append('high_risk_geolocation')
        
        if features.get('attack_frequency', 0) > 0.8:
            indicators.append('high_frequency_attacks')
        
        if features.get('authentication_attempts', 0) > 5:
            indicators.append('multiple_auth_attempts')
        
        honeypot_type = attack_event.get('honeypot_type', '')
        if honeypot_type == 'ssh' and features.get('brute_force_pattern', 0) == 1:
            indicators.append('brute_force_pattern')
        
        return indicators

    def _calculate_risk_score(self, features: Dict[str, Any], threat_level: str) -> float:
        base_score = 0.0
        
        threat_weights = {'low': 0.2, 'medium': 0.5, 'high': 0.8, 'critical': 1.0}
        base_score += threat_weights.get(threat_level, 0.2)
        
        risk_factors = [
            'payload_length',
            'suspicious_user_agent', 
            'unusual_working_hours',
            'geo_risk_score',
            'attack_frequency',
            'brute_force_pattern'
        ]
        
        for factor in risk_factors:
            if features.get(factor, 0) > 0.5:
                base_score += 0.1
        
        return min(base_score, 1.0)

    def _get_probability_distribution(self, probabilities: np.ndarray) -> Dict[str, float]:
        return {
            level: float(prob) 
            for level, prob in zip(self.threat_levels, probabilities)
        }

    def _fallback_classification(self, attack_event: Dict[str, Any]) -> Dict[str, Any]:
        features = self.feature_engineer.extract_threat_features(attack_event)
        
        risk_score = 0.0
        indicators = []
        
        if features.get('suspicious_user_agent', 0) == 1:
            risk_score += 0.3
            indicators.append('suspicious_user_agent')
        
        if features.get('authentication_attempts', 0) > 3:
            risk_score += 0.2
            indicators.append('multiple_auth_attempts')
        
        if features.get('geo_risk_score', 0) > 0.5:
            risk_score += 0.2
            indicators.append('suspicious_geolocation')
        
        if risk_score > 0.7:
            threat_level = 'high'
        elif risk_score > 0.4:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        
        return {
            'threat_level': threat_level,
            'confidence': risk_score,
            'risk_score': risk_score,
            'threat_indicators': indicators,
            'features': features,
            'fallback': True
        }

    def batch_classify(self, attack_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        
        for event in attack_events:
            result = self.classify_threat_level(event)
            results.append(result)
        
        return results

    def get_classification_rules(self) -> Dict[str, Any]:
        return {
            'feature_weights': self.get_feature_importance(),
            'risk_thresholds': {
                'low': 0.0,
                'medium': 0.4,
                'high': 0.7,
                'critical': 0.9
            },
            'important_indicators': [
                'suspicious_user_agent',
                'multiple_auth_attempts', 
                'unusual_timing',
                'high_risk_geolocation',
                'brute_force_pattern'
            ]
        }

def classify_threat_level(attack_event: Dict[str, Any]) -> Dict[str, Any]:
    classifier = ThreatClassifier()
    
    if not classifier.load_model():
        logger.warning("Threat classifier model not loaded, using rule-based classification")
        return _fallback_threat_classification(attack_event)
    
    return classifier.classify_threat_level(attack_event)

def _fallback_threat_classification(attack_event: Dict[str, Any]) -> Dict[str, Any]:
    features = FeatureEngineer().extract_threat_features(attack_event)
    
    risk_score = 0.0
    indicators = []
    
    honeypot_type = attack_event.get('honeypot_type', '')
    source_ip = attack_event.get('source_ip', '')
    
    if honeypot_type == 'ssh':
        risk_score += 0.3
        indicators.append('ssh_attack')
    
    if features.get('suspicious_user_agent', 0) == 1:
        risk_score += 0.2
        indicators.append('suspicious_user_agent')
    
    if any(blocked in source_ip for blocked in ['192.168.', '10.0.', '172.16.']):
        risk_score -= 0.1
    
    if risk_score > 0.5:
        threat_level = 'high'
    elif risk_score > 0.2:
        threat_level = 'medium'
    else:
        threat_level = 'low'
    
    return {
        'threat_level': threat_level,
        'confidence': max(risk_score, 0.1),
        'risk_score': risk_score,
        'threat_indicators': indicators,
        'features': features,
        'fallback': True
    }