"""
Honeypot CTDR - Machine Learning Module
AI/ML models for threat detection and behavior prediction
"""

from app.ml.base_model import BaseMLModel, ModelType
from app.ml.url_detector import URLDetector
from app.ml.behavior_predictor import BehaviorPredictor
from app.ml.threat_classifier import ThreatClassifier
from app.ml.feature_engineer import FeatureEngineer
from app.ml.model_trainer import ModelTrainer
from app.ml.shap_explainer import SHAPExplainer

from app.ml.url_detector import detect_malicious_url
from app.ml.behavior_predictor import predict_attacker_sequence
from app.ml.threat_classifier import classify_threat_level
from app.ml.feature_engineer import extract_features
from app.ml.model_trainer import train_all_models
from app.ml.shap_explainer import explain_prediction

__all__ = [
    "BaseMLModel",
    "ModelType",
    "URLDetector",
    "BehaviorPredictor", 
    "ThreatClassifier",
    "FeatureEngineer",
    "ModelTrainer",
    "SHAPExplainer",
    "detect_malicious_url",
    "predict_attacker_sequence",
    "classify_threat_level",
    "extract_features",
    "train_all_models",
    "explain_prediction"
]