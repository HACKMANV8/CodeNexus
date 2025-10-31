"""
Base ML Model Class and Common Functionality
"""

import logging
import pickle
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from pathlib import Path
from datetime import datetime

from app.core.config import settings

logger = logging.getLogger(__name__)

class ModelType(Enum):
    URL_DETECTOR = "url_detector"
    BEHAVIOR_PREDICTOR = "behavior_predictor"
    THREAT_CLASSIFIER = "threat_classifier"
    ANOMALY_DETECTOR = "anomaly_detector"

class BaseMLModel(ABC):
    def __init__(self, model_type: ModelType, version: str = "1.0"):
        self.model_type = model_type
        self.version = version
        self.model = None
        self.is_trained = False
        self.feature_names = []
        self.model_path = settings.MODELS_DIR / model_type.value
        self.metadata = {
            "model_type": model_type.value,
            "version": version,
            "created_at": datetime.utcnow(),
            "last_trained": None,
            "performance_metrics": {},
            "feature_count": 0
        }

    @abstractmethod
    def preprocess_data(self, data: Any) -> Any:
        pass

    @abstractmethod
    def train(self, X, y, **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def predict(self, X) -> Any:
        pass

    @abstractmethod
    def predict_proba(self, X) -> Any:
        pass

    def save_model(self, file_path: Optional[Path] = None) -> bool:
        try:
            if file_path is None:
                file_path = self.model_path / f"model_v{self.version}.pkl"
            
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            model_data = {
                'model': self.model,
                'metadata': self.metadata,
                'feature_names': self.feature_names,
                'is_trained': self.is_trained
            }
            
            with open(file_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            logger.info(f"Model saved to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False

    def load_model(self, file_path: Optional[Path] = None) -> bool:
        try:
            if file_path is None:
                file_path = self.model_path / f"model_v{self.version}.pkl"
            
            if not file_path.exists():
                logger.warning(f"Model file not found: {file_path}")
                return False
            
            with open(file_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.metadata = model_data['metadata']
            self.feature_names = model_data['feature_names']
            self.is_trained = model_data['is_trained']
            
            logger.info(f"Model loaded from {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    def evaluate(self, X_test, y_test) -> Dict[str, float]:
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation")
        
        try:
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            from sklearn.metrics import classification_report, confusion_matrix
            
            predictions = self.predict(X_test)
            probabilities = self.predict_proba(X_test)
            
            accuracy = accuracy_score(y_test, predictions)
            precision = precision_score(y_test, predictions, average='weighted', zero_division=0)
            recall = recall_score(y_test, predictions, average='weighted', zero_division=0)
            f1 = f1_score(y_test, predictions, average='weighted', zero_division=0)
            
            metrics = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'confusion_matrix': confusion_matrix(y_test, predictions).tolist(),
                'classification_report': classification_report(y_test, predictions, output_dict=True)
            }
            
            self.metadata['performance_metrics'] = metrics
            self.metadata['last_evaluated'] = datetime.utcnow().isoformat()
            
            return metrics
            
        except Exception as e:
            logger.error(f"Model evaluation failed: {e}")
            return {}

    def get_feature_importance(self) -> Dict[str, float]:
        if not self.is_trained:
            return {}
        
        try:
            if hasattr(self.model, 'feature_importances_'):
                importance_dict = dict(zip(self.feature_names, self.model.feature_importances_))
                return {k: v for k, v in sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)}
            else:
                return {}
                
        except Exception as e:
            logger.error(f"Failed to get feature importance: {e}")
            return {}

    def get_model_info(self) -> Dict[str, Any]:
        return {
            'model_type': self.model_type.value,
            'version': self.version,
            'is_trained': self.is_trained,
            'feature_count': len(self.feature_names),
            'metadata': self.metadata
        }

    def validate_input(self, data: Any) -> bool:
        if not self.is_trained:
            logger.warning("Model is not trained")
            return False
        
        if len(self.feature_names) == 0:
            logger.warning("No feature names defined")
            return False
        
        return True

    def update_metadata(self, updates: Dict[str, Any]):
        self.metadata.update(updates)
        self.metadata['last_updated'] = datetime.utcnow().isoformat()

class ModelFactory:
    def __init__(self):
        self.model_registry = {}

    def register_model(self, model_type: ModelType, model_class):
        self.model_registry[model_type] = model_class

    def create_model(self, model_type: ModelType, **kwargs) -> BaseMLModel:
        if model_type not in self.model_registry:
            raise ValueError(f"Model type {model_type} not registered")
        
        return self.model_registry[model_type](**kwargs)

    def load_all_models(self) -> Dict[ModelType, BaseMLModel]:
        loaded_models = {}
        
        for model_type in self.model_registry:
            try:
                model = self.create_model(model_type)
                if model.load_model():
                    loaded_models[model_type] = model
                    logger.info(f"Loaded {model_type.value} model")
                else:
                    logger.warning(f"Failed to load {model_type.value} model")
            except Exception as e:
                logger.error(f"Error loading {model_type.value} model: {e}")
        
        return loaded_models