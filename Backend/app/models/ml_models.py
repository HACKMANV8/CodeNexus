"""
Machine Learning data models for feature engineering and predictions
"""

from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum

class ModelType(str, Enum):
    THREAT_CLASSIFIER = "threat_classifier"
    BEHAVIOR_PREDICTOR = "behavior_predictor"
    URL_DETECTOR = "url_detector"
    ANOMALY_DETECTOR = "anomaly_detector"

class FeatureCategory(str, Enum):
    NETWORK = "network"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    PAYLOAD = "payload"
    GEOGRAPHICAL = "geographical"

class MLFeatureSet(BaseModel):
    feature_set_id: str
    event_id: str
    features: Dict[str, float]
    feature_categories: List[FeatureCategory]
    created_at: datetime
    version: str

class ModelPrediction(BaseModel):
    prediction_id: str
    model_type: ModelType
    input_features: Dict[str, Any]
    output_prediction: str
    confidence: float
    probabilities: Dict[str, float]
    timestamp: datetime
    model_version: str
    feature_importance: Optional[Dict[str, float]]

class SHAPExplanation(BaseModel):
    explanation_id: str
    prediction_id: str
    base_value: float
    values: List[float]
    feature_names: List[str]
    data: List[float]
    feature_importance: Dict[str, float]
    created_at: datetime

class ModelPerformance(BaseModel):
    model_name: str
    version: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    confusion_matrix: Dict[str, int]
    training_date: datetime
    evaluation_date: datetime
    dataset_size: int
    feature_count: int

class TrainingMetrics(BaseModel):
    training_id: str
    model_name: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    initial_accuracy: float
    final_accuracy: float
    loss_history: List[float]
    accuracy_history: List[float]
    learning_rate: float
    batch_size: int
    epochs: int
    dataset_info: Dict[str, Any]