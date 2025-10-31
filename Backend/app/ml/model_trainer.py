"""
Model Training and Management
Orchestrates training of all ML models
"""

import logging
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

from app.ml.base_model import ModelType, ModelFactory
from app.ml.url_detector import URLDetector
from app.ml.behavior_predictor import BehaviorPredictor
from app.ml.threat_classifier import ThreatClassifier
from app.core.config import settings

logger = logging.getLogger(__name__)

class ModelTrainer:
    def __init__(self):
        self.model_factory = ModelFactory()
        self._register_models()
        self.training_history = []

    def _register_models(self):
        self.model_factory.register_model(ModelType.URL_DETECTOR, URLDetector)
        self.model_factory.register_model(ModelType.BEHAVIOR_PREDICTOR, BehaviorPredictor)
        self.model_factory.register_model(ModelType.THREAT_CLASSIFIER, ThreatClassifier)

    def train_all_models(self, training_data: Dict[str, Any]) -> Dict[str, Any]:
        results = {}
        
        try:
            logger.info("Starting training for all ML models")
            
            if 'url_data' in training_data:
                results['url_detector'] = self.train_url_detector(training_data['url_data'])
            
            if 'behavior_data' in training_data:
                results['behavior_predictor'] = self.train_behavior_predictor(training_data['behavior_data'])
            
            if 'threat_data' in training_data:
                results['threat_classifier'] = self.train_threat_classifier(training_data['threat_data'])
            
            self._record_training_session(results)
            logger.info("Completed training for all ML models")
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            results['error'] = str(e)
        
        return results

    def train_url_detector(self, training_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            model = self.model_factory.create_model(ModelType.URL_DETECTOR)
            
            urls = training_data.get('urls', [])
            labels = training_data.get('labels', [])
            
            if len(urls) < 100:
                logger.warning(f"Insufficient URL training data: {len(urls)} samples")
                return {'status': 'insufficient_data', 'samples': len(urls)}
            
            metrics = model.train(urls, labels, epochs=100)
            
            if model.is_trained:
                model.save_model()
                logger.info(f"URL detector trained successfully on {len(urls)} samples")
                return {'status': 'success', 'metrics': metrics, 'samples': len(urls)}
            else:
                return {'status': 'training_failed', 'samples': len(urls)}
                
        except Exception as e:
            logger.error(f"URL detector training failed: {e}")
            return {'status': 'error', 'error': str(e)}

    def train_behavior_predictor(self, training_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            model = self.model_factory.create_model(ModelType.BEHAVIOR_PREDICTOR)
            
            sequences = training_data.get('sequences', [])
            labels = training_data.get('labels', [])
            
            if len(sequences) < 50:
                logger.warning(f"Insufficient behavior training data: {len(sequences)} sequences")
                return {'status': 'insufficient_data', 'sequences': len(sequences)}
            
            metrics = model.train(sequences, labels, epochs=50)
            
            if model.is_trained:
                model.save_model()
                logger.info(f"Behavior predictor trained successfully on {len(sequences)} sequences")
                return {'status': 'success', 'metrics': metrics, 'sequences': len(sequences)}
            else:
                return {'status': 'training_failed', 'sequences': len(sequences)}
                
        except Exception as e:
            logger.error(f"Behavior predictor training failed: {e}")
            return {'status': 'error', 'error': str(e)}

    def train_threat_classifier(self, training_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            model = self.model_factory.create_model(ModelType.THREAT_CLASSIFIER)
            
            attack_events = training_data.get('attack_events', [])
            labels = training_data.get('labels', [])
            
            if len(attack_events) < 200:
                logger.warning(f"Insufficient threat training data: {len(attack_events)} samples")
                return {'status': 'insufficient_data', 'samples': len(attack_events)}
            
            metrics = model.train(attack_events, labels)
            
            if model.is_trained:
                model.save_model()
                logger.info(f"Threat classifier trained successfully on {len(attack_events)} samples")
                return {'status': 'success', 'metrics': metrics, 'samples': len(attack_events)}
            else:
                return {'status': 'training_failed', 'samples': len(attack_events)}
                
        except Exception as e:
            logger.error(f"Threat classifier training failed: {e}")
            return {'status': 'error', 'error': str(e)}

    def evaluate_all_models(self, test_data: Dict[str, Any]) -> Dict[str, Any]:
        results = {}
        
        try:
            loaded_models = self.model_factory.load_all_models()
            
            for model_type, model in loaded_models.items():
                if model_type == ModelType.URL_DETECTOR and 'url_test' in test_data:
                    X_test = test_data['url_test']['urls']
                    y_test = test_data['url_test']['labels']
                    results['url_detector'] = model.evaluate(X_test, y_test)
                
                elif model_type == ModelType.BEHAVIOR_PREDICTOR and 'behavior_test' in test_data:
                    X_test = test_data['behavior_test']['sequences']
                    y_test = test_data['behavior_test']['labels']
                    results['behavior_predictor'] = model.evaluate(X_test, y_test)
                
                elif model_type == ModelType.THREAT_CLASSIFIER and 'threat_test' in test_data:
                    X_test = test_data['threat_test']['attack_events']
                    y_test = test_data['threat_test']['labels']
                    results['threat_classifier'] = model.evaluate(X_test, y_test)
            
            logger.info("Completed evaluation for all ML models")
            
        except Exception as e:
            logger.error(f"Model evaluation failed: {e}")
            results['error'] = str(e)
        
        return results

    def get_model_status(self) -> Dict[str, Any]:
        status = {}
        
        try:
            loaded_models = self.model_factory.load_all_models()
            
            for model_type, model in loaded_models.items():
                status[model_type.value] = {
                    'is_loaded': model is not None,
                    'is_trained': model.is_trained if model else False,
                    'version': model.version if model else 'unknown',
                    'last_trained': model.metadata.get('last_trained') if model else None,
                    'performance': model.metadata.get('performance_metrics', {}) if model else {}
                }
            
            status['total_models'] = len(loaded_models)
            status['loaded_models'] = len([m for m in loaded_models.values() if m is not None])
            
        except Exception as e:
            logger.error(f"Failed to get model status: {e}")
            status['error'] = str(e)
        
        return status

    def retrain_models(self, new_data: Dict[str, Any]) -> Dict[str, Any]:
        results = {}
        
        try:
            current_models = self.model_factory.load_all_models()
            
            for model_type, model in current_models.items():
                if model and model.is_trained:
                    if model_type == ModelType.URL_DETECTOR and 'url_data' in new_data:
                        results['url_detector'] = self._incremental_train_url_detector(model, new_data['url_data'])
                    
                    elif model_type == ModelType.BEHAVIOR_PREDICTOR and 'behavior_data' in new_data:
                        results['behavior_predictor'] = self._incremental_train_behavior_predictor(model, new_data['behavior_data'])
                    
                    elif model_type == ModelType.THREAT_CLASSIFIER and 'threat_data' in new_data:
                        results['threat_classifier'] = self._incremental_train_threat_classifier(model, new_data['threat_data'])
            
            logger.info("Completed incremental training for models")
            
        except Exception as e:
            logger.error(f"Incremental training failed: {e}")
            results['error'] = str(e)
        
        return results

    def _incremental_train_url_detector(self, model: URLDetector, new_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            urls = new_data.get('urls', [])
            labels = new_data.get('labels', [])
            
            if len(urls) < 10:
                return {'status': 'insufficient_new_data', 'samples': len(urls)}
            
            metrics = model.train(urls, labels, epochs=20)
            model.save_model()
            
            return {'status': 'success', 'metrics': metrics, 'new_samples': len(urls)}
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def _incremental_train_behavior_predictor(self, model: BehaviorPredictor, new_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            sequences = new_data.get('sequences', [])
            labels = new_data.get('labels', [])
            
            if len(sequences) < 5:
                return {'status': 'insufficient_new_data', 'sequences': len(sequences)}
            
            metrics = model.train(sequences, labels, epochs=10)
            model.save_model()
            
            return {'status': 'success', 'metrics': metrics, 'new_sequences': len(sequences)}
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def _incremental_train_threat_classifier(self, model: ThreatClassifier, new_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            attack_events = new_data.get('attack_events', [])
            labels = new_data.get('labels', [])
            
            if len(attack_events) < 20:
                return {'status': 'insufficient_new_data', 'samples': len(attack_events)}
            
            metrics = model.train(attack_events, labels)
            model.save_model()
            
            return {'status': 'success', 'metrics': metrics, 'new_samples': len(attack_events)}
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def _record_training_session(self, results: Dict[str, Any]):
        session_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'results': results,
            'successful_models': sum(1 for r in results.values() if r.get('status') == 'success')
        }
        
        self.training_history.append(session_record)
        
        if len(self.training_history) > 50:
            self.training_history = self.training_history[-50:]

    def get_training_history(self) -> List[Dict[str, Any]]:
        return self.training_history

    def generate_training_report(self) -> Dict[str, Any]:
        status = self.get_model_status()
        history = self.training_history
        
        recent_success = sum(1 for session in history[-5:] if session['successful_models'] > 0)
        
        return {
            'current_status': status,
            'recent_training_sessions': len(history),
            'recent_success_rate': recent_success / 5 if history else 0,
            'last_training_session': history[-1] if history else None,
            'recommendations': self._generate_training_recommendations(status)
        }

    def _generate_training_recommendations(self, status: Dict[str, Any]) -> List[str]:
        recommendations = []
        
        for model_name, model_status in status.items():
            if model_name == 'total_models' or model_name == 'loaded_models':
                continue
            
            if not model_status.get('is_loaded', False):
                recommendations.append(f"Load {model_name} model")
            elif not model_status.get('is_trained', False):
                recommendations.append(f"Train {model_name} model")
            else:
                performance = model_status.get('performance', {})
                if performance.get('accuracy', 0) < 0.8:
                    recommendations.append(f"Retrain {model_name} for better accuracy")
        
        if not recommendations:
            recommendations.append("All models are in good condition")
        
        return recommendations

def train_all_models(training_data: Dict[str, Any]) -> Dict[str, Any]:
    trainer = ModelTrainer()
    return trainer.train_all_models(training_data)