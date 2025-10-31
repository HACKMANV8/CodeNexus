import pytest
import numpy as np
from unittest.mock import patch, MagicMock

from app.ml.url_detector import URLDetector
from app.ml.threat_classifier import ThreatClassifier
from app.ml.behavior_predictor import BehaviorPredictor
from app.models.ml_models import MLPrediction, FeatureSet

class TestURLDetector:
    def test_url_detector_initialization(self):
        detector = URLDetector()
        assert detector.model is None
        assert detector.is_trained == False

    def test_extract_url_features(self):
        detector = URLDetector()
        features = detector._extract_features("http://malicious-site.com/login.php")
        
        assert "length" in features
        assert "num_digits" in features
        assert "entropy" in features
        assert features["length"] == 37

    @patch('app.ml.url_detector.lgb.Booster')
    def test_url_prediction(self, mock_lgb):
        detector = URLDetector()
        detector.model = mock_lgb
        detector.is_trained = True
        
        mock_lgb.predict.return_value = np.array([0.9])
        
        result = detector.predict("http://phishing-site.com")
        assert result["is_malicious"] == True
        assert result["confidence"] == 0.9

class TestThreatClassifier:
    def test_threat_classifier_initialization(self):
        classifier = ThreatClassifier()
        assert classifier.confidence_threshold == 0.85

    def test_feature_engineering(self):
        classifier = ThreatClassifier()
        attack_data = {
            "source_ip": "192.168.1.100",
            "request_count": 15,
            "error_count": 12,
            "payload_length": 1500
        }
        
        features = classifier._engineer_features(attack_data)
        assert "request_frequency" in features
        assert "error_rate" in features

    @patch('app.ml.threat_classifier.IsolationForest')
    def test_anomaly_detection(self, mock_isolation):
        classifier = ThreatClassifier()
        classifier.anomaly_detector = mock_isolation
        
        mock_isolation.predict.return_value = np.array([-1])
        
        result = classifier.detect_anomaly({"request_count": 1000})
        assert result["is_anomaly"] == True

class TestBehaviorPredictor:
    def test_behavior_predictor_initialization(self):
        predictor = BehaviorPredictor()
        assert predictor.sequence_length == 10

    def test_sequence_creation(self):
        predictor = BehaviorPredictor()
        events = [{"type": "ssh_attempt"} for _ in range(15)]
        
        sequences = predictor._create_sequences(events)
        assert len(sequences) == 6  # 15 events with sequence length 10

    @patch('app.ml.behavior_predictor.tf.keras.Model')
    def test_next_action_prediction(self, mock_model):
        predictor = BehaviorPredictor()
        predictor.model = mock_model
        
        mock_model.predict.return_value = np.array([[0.1, 0.8, 0.1]])
        
        result = predictor.predict_next_action([{"type": "ssh_attempt"}])
        assert "predicted_action" in result
        assert "confidence" in result