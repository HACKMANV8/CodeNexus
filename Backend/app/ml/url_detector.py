"""
URL Detection ML Model
Detects malicious URLs and phishing attempts
"""

import logging
import re
import numpy as np
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import tldextract

from app.ml.base_model import BaseMLModel, ModelType
from app.ml.feature_engineer import FeatureEngineer

logger = logging.getLogger(__name__)

class URLDetector(BaseMLModel):
    def __init__(self, version: str = "1.0"):
        super().__init__(ModelType.URL_DETECTOR, version)
        self.feature_engineer = FeatureEngineer()
        self._initialize_model()

    def _initialize_model(self):
        try:
            from sklearn.ensemble import RandomForestClassifier
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            logger.info("URL detector model initialized")
        except Exception as e:
            logger.error(f"Failed to initialize URL detector model: {e}")
            self.model = None

    def preprocess_data(self, urls: List[str]) -> np.ndarray:
        features = []
        
        for url in urls:
            url_features = self.feature_engineer.extract_url_features(url)
            feature_vector = list(url_features.values())
            features.append(feature_vector)
        
        self.feature_names = list(url_features.keys()) if url_features else []
        return np.array(features)

    def train(self, X, y, **kwargs) -> Dict[str, Any]:
        try:
            if self.model is None:
                self._initialize_model()
            
            X_processed = self.preprocess_data(X)
            
            self.model.fit(X_processed, y)
            self.is_trained = True
            self.metadata['last_trained'] = datetime.utcnow().isoformat()
            self.metadata['training_samples'] = len(X)
            self.metadata['feature_count'] = X_processed.shape[1]
            
            training_metrics = self.evaluate(X_processed, y)
            
            logger.info(f"URL detector trained on {len(X)} samples")
            return training_metrics
            
        except Exception as e:
            logger.error(f"URL detector training failed: {e}")
            return {}

    def predict(self, urls: List[str]) -> np.ndarray:
        if not self.validate_input(urls):
            return np.array([])
        
        try:
            X_processed = self.preprocess_data(urls)
            predictions = self.model.predict(X_processed)
            return predictions
            
        except Exception as e:
            logger.error(f"URL detection prediction failed: {e}")
            return np.array([])

    def predict_proba(self, urls: List[str]) -> np.ndarray:
        if not self.validate_input(urls):
            return np.array([])
        
        try:
            X_processed = self.preprocess_data(urls)
            probabilities = self.model.predict_proba(X_processed)
            return probabilities
            
        except Exception as e:
            logger.error(f"URL detection probability prediction failed: {e}")
            return np.array([])

    def detect_malicious_url(self, url: str) -> Dict[str, Any]:
        try:
            prediction = self.predict([url])
            probability = self.predict_proba([url])
            
            is_malicious = bool(prediction[0]) if len(prediction) > 0 else False
            confidence = float(probability[0][1]) if len(probability) > 0 else 0.0
            
            features = self.feature_engineer.extract_url_features(url)
            risk_factors = self._identify_risk_factors(url, features)
            
            return {
                'url': url,
                'is_malicious': is_malicious,
                'confidence': confidence,
                'risk_factors': risk_factors,
                'features': features
            }
            
        except Exception as e:
            logger.error(f"URL detection failed: {e}")
            return {
                'url': url,
                'is_malicious': False,
                'confidence': 0.0,
                'risk_factors': [],
                'features': {},
                'error': str(e)
            }

    def _identify_risk_factors(self, url: str, features: Dict[str, Any]) -> List[str]:
        risk_factors = []
        
        if features.get('url_length', 0) > 150:
            risk_factors.append('long_url')
        
        if features.get('num_dots', 0) > 5:
            risk_factors.append('many_dots')
        
        if features.get('num_hyphens', 0) > 5:
            risk_factors.append('many_hyphens')
        
        if features.get('num_subdomains', 0) > 3:
            risk_factors.append('many_subdomains')
        
        if features.get('has_ip_address', 0) == 1:
            risk_factors.append('contains_ip')
        
        if features.get('suspicious_tld', 0) == 1:
            risk_factors.append('suspicious_tld')
        
        if features.get('entropy', 0) > 4.5:
            risk_factors.append('high_entropy')
        
        return risk_factors

    def batch_detect(self, urls: List[str]) -> List[Dict[str, Any]]:
        results = []
        
        for url in urls:
            result = self.detect_malicious_url(url)
            results.append(result)
        
        return results

    def get_detection_stats(self) -> Dict[str, Any]:
        model_info = self.get_model_info()
        
        return {
            'model_info': model_info,
            'feature_importance': self.get_feature_importance(),
            'risk_patterns': {
                'long_url_threshold': 150,
                'max_dots': 5,
                'max_hyphens': 5,
                'max_subdomains': 3,
                'high_entropy_threshold': 4.5
            }
        }

def detect_malicious_url(url: str) -> Dict[str, Any]:
    detector = URLDetector()
    
    if not detector.load_model():
        logger.warning("URL detector model not loaded, using fallback detection")
        return _fallback_url_detection(url)
    
    return detector.detect_malicious_url(url)

def _fallback_url_detection(url: str) -> Dict[str, Any]:
    features = FeatureEngineer().extract_url_features(url)
    
    risk_score = 0
    risk_factors = []
    
    if features.get('has_ip_address', 0) == 1:
        risk_score += 0.3
        risk_factors.append('contains_ip')
    
    if features.get('suspicious_tld', 0) == 1:
        risk_score += 0.2
        risk_factors.append('suspicious_tld')
    
    if features.get('url_length', 0) > 100:
        risk_score += 0.1
        risk_factors.append('long_url')
    
    if features.get('num_subdomains', 0) > 2:
        risk_score += 0.1
        risk_factors.append('multiple_subdomains')
    
    is_malicious = risk_score > 0.3
    
    return {
        'url': url,
        'is_malicious': is_malicious,
        'confidence': min(risk_score, 1.0),
        'risk_factors': risk_factors,
        'features': features,
        'fallback': True
    }