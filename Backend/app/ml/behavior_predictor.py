"""
Behavior Prediction ML Model
Predicts attacker behavior and next actions
"""

import logging
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import torch
import torch.nn as nn

from app.ml.base_model import BaseMLModel, ModelType
from app.ml.feature_engineer import FeatureEngineer

logger = logging.getLogger(__name__)

class BehaviorPredictor(BaseMLModel):
    def __init__(self, version: str = "1.0"):
        super().__init__(ModelType.BEHAVIOR_PREDICTOR, version)
        self.feature_engineer = FeatureEngineer()
        self.sequence_length = 10
        self.num_features = 20
        self._initialize_model()

    def _initialize_model(self):
        try:
            self.model = BehaviorLSTM(
                input_size=self.num_features,
                hidden_size=64,
                num_layers=2,
                output_size=5,
                dropout=0.2
            )
            self.optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
            self.criterion = nn.CrossEntropyLoss()
            logger.info("Behavior predictor LSTM model initialized")
        except Exception as e:
            logger.error(f"Failed to initialize behavior predictor: {e}")
            self.model = None

    def preprocess_data(self, sequences: List[List[Dict[str, Any]]]) -> torch.Tensor:
        processed_sequences = []
        
        for sequence in sequences:
            sequence_features = []
            for event in sequence:
                features = self.feature_engineer.extract_behavioral_features(event)
                feature_vector = list(features.values())[:self.num_features]
                
                if len(feature_vector) < self.num_features:
                    feature_vector.extend([0] * (self.num_features - len(feature_vector)))
                
                sequence_features.append(feature_vector)
            
            if len(sequence_features) < self.sequence_length:
                padding = [[0] * self.num_features] * (self.sequence_length - len(sequence_features))
                sequence_features = padding + sequence_features
            else:
                sequence_features = sequence_features[-self.sequence_length:]
            
            processed_sequences.append(sequence_features)
        
        self.feature_names = list(features.keys())[:self.num_features] if sequences else []
        return torch.FloatTensor(processed_sequences)

    def train(self, X, y, **kwargs) -> Dict[str, Any]:
        try:
            if self.model is None:
                self._initialize_model()
            
            X_tensor = self.preprocess_data(X)
            y_tensor = torch.LongTensor(y)
            
            self.model.train()
            losses = []
            
            for epoch in range(kwargs.get('epochs', 50)):
                self.optimizer.zero_grad()
                outputs = self.model(X_tensor)
                loss = self.criterion(outputs, y_tensor)
                loss.backward()
                self.optimizer.step()
                losses.append(loss.item())
            
            self.is_trained = True
            self.metadata['last_trained'] = datetime.utcnow().isoformat()
            self.metadata['training_samples'] = len(X)
            self.metadata['sequence_length'] = self.sequence_length
            self.metadata['training_loss'] = losses[-1] if losses else 0
            
            training_accuracy = self._evaluate_training(X_tensor, y_tensor)
            self.metadata['training_accuracy'] = training_accuracy
            
            logger.info(f"Behavior predictor trained on {len(X)} sequences")
            
            return {
                'final_loss': losses[-1] if losses else 0,
                'training_accuracy': training_accuracy,
                'loss_history': losses
            }
            
        except Exception as e:
            logger.error(f"Behavior predictor training failed: {e}")
            return {}

    def predict(self, sequences: List[List[Dict[str, Any]]]) -> np.ndarray:
        if not self.validate_input(sequences):
            return np.array([])
        
        try:
            X_tensor = self.preprocess_data(sequences)
            self.model.eval()
            
            with torch.no_grad():
                outputs = self.model(X_tensor)
                predictions = torch.argmax(outputs, dim=1)
            
            return predictions.numpy()
            
        except Exception as e:
            logger.error(f"Behavior prediction failed: {e}")
            return np.array([])

    def predict_proba(self, sequences: List[List[Dict[str, Any]]]) -> np.ndarray:
        if not self.validate_input(sequences):
            return np.array([])
        
        try:
            X_tensor = self.preprocess_data(sequences)
            self.model.eval()
            
            with torch.no_grad():
                outputs = self.model(X_tensor)
                probabilities = torch.softmax(outputs, dim=1)
            
            return probabilities.numpy()
            
        except Exception as e:
            logger.error(f"Behavior probability prediction failed: {e}")
            return np.array([])

    def predict_attacker_behavior(self, attacker_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            if len(attacker_history) < 3:
                return self._predict_with_limited_history(attacker_history)
            
            sequence = self._prepare_sequence(attacker_history)
            prediction = self.predict([sequence])
            probability = self.predict_proba([sequence])
            
            next_action = self._map_prediction_to_action(prediction[0])
            confidence = float(np.max(probability[0]))
            
            behavior_pattern = self._analyze_behavior_pattern(attacker_history)
            risk_assessment = self._assess_risk(attacker_history, next_action)
            
            return {
                'next_likely_action': next_action,
                'confidence': confidence,
                'behavior_pattern': behavior_pattern,
                'risk_assessment': risk_assessment,
                'predicted_actions': self._get_action_sequence(probability[0]),
                'timestamp': datetime.utcnow()
            }
            
        except Exception as e:
            logger.error(f"Attacker behavior prediction failed: {e}")
            return {
                'next_likely_action': 'unknown',
                'confidence': 0.0,
                'behavior_pattern': 'insufficient_data',
                'risk_assessment': 'low',
                'error': str(e)
            }

    def _prepare_sequence(self, history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return history[-self.sequence_length:]

    def _map_prediction_to_action(self, prediction: int) -> str:
        action_map = {
            0: 'reconnaissance',
            1: 'exploitation', 
            2: 'persistence',
            3: 'lateral_movement',
            4: 'data_exfiltration'
        }
        return action_map.get(prediction, 'unknown')

    def _analyze_behavior_pattern(self, history: List[Dict[str, Any]]) -> str:
        if len(history) < 2:
            return 'initial_probing'
        
        attack_types = [event.get('honeypot_type', 'unknown') for event in history]
        unique_attacks = len(set(attack_types))
        
        if unique_attacks > 3:
            return 'comprehensive_attack'
        elif any('ssh' in attack for attack in attack_types):
            return 'brute_force_pattern'
        elif any('web' in attack for attack in attack_types):
            return 'web_application_attack'
        else:
            return 'mixed_activity'

    def _assess_risk(self, history: List[Dict[str, Any]], next_action: str) -> str:
        risk_score = 0
        
        risk_score += len(history) * 0.1
        
        malicious_count = sum(1 for event in history if event.get('is_malicious', False))
        risk_score += malicious_count * 0.3
        
        if next_action in ['exploitation', 'data_exfiltration']:
            risk_score += 0.4
        
        if risk_score > 0.8:
            return 'critical'
        elif risk_score > 0.6:
            return 'high'
        elif risk_score > 0.4:
            return 'medium'
        else:
            return 'low'

    def _get_action_sequence(self, probabilities: np.ndarray) -> List[Dict[str, Any]]:
        action_names = ['reconnaissance', 'exploitation', 'persistence', 'lateral_movement', 'data_exfiltration']
        
        return [
            {'action': action, 'probability': float(prob)}
            for action, prob in zip(action_names, probabilities)
        ]

    def _predict_with_limited_history(self, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not history:
            return {
                'next_likely_action': 'reconnaissance',
                'confidence': 0.5,
                'behavior_pattern': 'initial_contact',
                'risk_assessment': 'low'
            }
        
        last_event = history[-1]
        honeypot_type = last_event.get('honeypot_type', 'unknown')
        
        if honeypot_type == 'ssh':
            return {
                'next_likely_action': 'exploitation',
                'confidence': 0.6,
                'behavior_pattern': 'authentication_attack',
                'risk_assessment': 'medium'
            }
        elif honeypot_type == 'web':
            return {
                'next_likely_action': 'persistence',
                'confidence': 0.55,
                'behavior_pattern': 'web_scanning',
                'risk_assessment': 'medium'
            }
        else:
            return {
                'next_likely_action': 'reconnaissance',
                'confidence': 0.5,
                'behavior_pattern': 'probing',
                'risk_assessment': 'low'
            }

    def _evaluate_training(self, X_tensor: torch.Tensor, y_tensor: torch.Tensor) -> float:
        self.model.eval()
        with torch.no_grad():
            outputs = self.model(X_tensor)
            predictions = torch.argmax(outputs, dim=1)
            accuracy = (predictions == y_tensor).float().mean()
        return accuracy.item()

class BehaviorLSTM(nn.Module):
    def __init__(self, input_size: int, hidden_size: int, num_layers: int, output_size: int, dropout: float = 0.2):
        super(BehaviorLSTM, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True, dropout=dropout)
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(hidden_size, output_size)
    
    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
        
        out, _ = self.lstm(x, (h0, c0))
        out = self.dropout(out[:, -1, :])
        out = self.fc(out)
        return out

def predict_attacker_sequence(attacker_history: List[Dict[str, Any]]) -> Dict[str, Any]:
    predictor = BehaviorPredictor()
    
    if not predictor.load_model():
        logger.warning("Behavior predictor model not loaded, using rule-based prediction")
        return _fallback_behavior_prediction(attacker_history)
    
    return predictor.predict_attacker_behavior(attacker_history)

def _fallback_behavior_prediction(attacker_history: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not attacker_history:
        return {
            'next_likely_action': 'reconnaissance',
            'confidence': 0.3,
            'behavior_pattern': 'initial_contact',
            'risk_assessment': 'low',
            'fallback': True
        }
    
    attack_count = len(attacker_history)
    malicious_count = sum(1 for event in attacker_history if event.get('is_malicious', False))
    
    if malicious_count > 5:
        next_action = 'data_exfiltration'
        confidence = 0.7
        risk = 'high'
    elif malicious_count > 2:
        next_action = 'persistence'
        confidence = 0.6
        risk = 'medium'
    else:
        next_action = 'exploitation'
        confidence = 0.5
        risk = 'low'
    
    return {
        'next_likely_action': next_action,
        'confidence': confidence,
        'behavior_pattern': 'escalating_attack',
        'risk_assessment': risk,
        'fallback': True
    }