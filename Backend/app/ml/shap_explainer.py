"""
SHAP Explanation Generator
Provides model interpretability and feature importance
"""

import logging
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
import shap

from app.ml.base_model import BaseMLModel

logger = logging.getLogger(__name__)

class SHAPExplainer:
    def __init__(self):
        self.explainers = {}
        self.background_data = {}

    def create_explainer(self, model: BaseMLModel, background_data: np.ndarray) -> bool:
        try:
            if model.model_type.value in self.explainers:
                logger.info(f"Explainer already exists for {model.model_type.value}")
                return True
            
            if background_data.size == 0:
                logger.warning(f"No background data provided for {model.model_type.value}")
                return False
            
            if hasattr(model.model, 'predict_proba'):
                explainer = shap.TreeExplainer(model.model, background_data)
            else:
                logger.warning(f"Model {model.model_type.value} doesn't support TreeExplainer")
                return False
            
            self.explainers[model.model_type.value] = explainer
            self.background_data[model.model_type.value] = background_data
            
            logger.info(f"Created SHAP explainer for {model.model_type.value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create SHAP explainer for {model.model_type.value}: {e}")
            return False

    def explain_prediction(self, model: BaseMLModel, input_data: np.ndarray) -> Dict[str, Any]:
        try:
            model_type = model.model_type.value
            
            if model_type not in self.explainers:
                logger.warning(f"No explainer found for {model_type}")
                return self._fallback_explanation(model, input_data)
            
            explainer = self.explainers[model_type]
            
            shap_values = explainer.shap_values(input_data)
            base_value = explainer.expected_value
            
            if isinstance(shap_values, list):
                shap_values = shap_values[1]
                if isinstance(base_value, list):
                    base_value = base_value[1]
            
            feature_importance = self._calculate_feature_importance(shap_values, model.feature_names)
            decision_plot = self._generate_decision_plot_data(base_value, shap_values[0], model.feature_names)
            
            explanation = {
                'shap_values': shap_values.tolist(),
                'base_value': float(base_value),
                'feature_names': model.feature_names,
                'feature_importance': feature_importance,
                'decision_plot': decision_plot,
                'prediction_confidence': self._get_prediction_confidence(model, input_data),
                'top_contributors': self._get_top_contributors(feature_importance, 5)
            }
            
            return explanation
            
        except Exception as e:
            logger.error(f"SHAP explanation failed for {model.model_type.value}: {e}")
            return self._fallback_explanation(model, input_data)

    def explain_batch_predictions(self, model: BaseMLModel, input_batch: np.ndarray) -> List[Dict[str, Any]]:
        explanations = []
        
        for i in range(len(input_batch)):
            single_input = input_batch[i:i+1]
            explanation = self.explain_prediction(model, single_input)
            explanations.append(explanation)
        
        return explanations

    def _calculate_feature_importance(self, shap_values: np.ndarray, feature_names: List[str]) -> Dict[str, float]:
        if len(shap_values.shape) > 1:
            shap_importance = np.mean(np.abs(shap_values), axis=0)
        else:
            shap_importance = np.abs(shap_values)
        
        importance_dict = {}
        for i, feature_name in enumerate(feature_names):
            if i < len(shap_importance):
                importance_dict[feature_name] = float(shap_importance[i])
        
        return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))

    def _generate_decision_plot_data(self, base_value: float, shap_values: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        cumulative_effect = base_value
        decision_steps = []
        
        for i, (feature_name, shap_value) in enumerate(zip(feature_names, shap_values)):
            cumulative_effect += shap_value
            decision_steps.append({
                'feature': feature_name,
                'shap_value': float(shap_value),
                'cumulative_effect': float(cumulative_effect),
                'step': i
            })
        
        return {
            'base_value': float(base_value),
            'final_value': float(cumulative_effect),
            'decision_steps': decision_steps
        }

    def _get_prediction_confidence(self, model: BaseMLModel, input_data: np.ndarray) -> float:
        try:
            if hasattr(model, 'predict_proba'):
                probabilities = model.predict_proba(input_data)
                return float(np.max(probabilities))
            else:
                return 0.5
        except:
            return 0.5

    def _get_top_contributors(self, feature_importance: Dict[str, float], top_n: int) -> List[Dict[str, Any]]:
        sorted_features = sorted(feature_importance.items(), key=lambda x: abs(x[1]), reverse=True)
        
        contributors = []
        for feature, importance in sorted_features[:top_n]:
            contributors.append({
                'feature': feature,
                'importance': importance,
                'direction': 'increases' if importance > 0 else 'decreases'
            })
        
        return contributors

    def _fallback_explanation(self, model: BaseMLModel, input_data: np.ndarray) -> Dict[str, Any]:
        logger.warning(f"Using fallback explanation for {model.model_type.value}")
        
        feature_importance = model.get_feature_importance()
        
        if not feature_importance:
            feature_importance = {name: 0.0 for name in model.feature_names}
        
        return {
            'shap_values': [],
            'base_value': 0.0,
            'feature_names': model.feature_names,
            'feature_importance': feature_importance,
            'decision_plot': {
                'base_value': 0.0,
                'final_value': 0.0,
                'decision_steps': []
            },
            'prediction_confidence': 0.5,
            'top_contributors': self._get_top_contributors(feature_importance, 5),
            'fallback': True
        }

    def get_global_feature_importance(self, model: BaseMLModel, sample_size: int = 100) -> Dict[str, Any]:
        try:
            model_type = model.model_type.value
            
            if model_type not in self.background_data:
                logger.warning(f"No background data for {model_type}")
                return {}
            
            background_data = self.background_data[model_type]
            
            if len(background_data) > sample_size:
                background_sample = background_data[np.random.choice(background_data.shape[0], sample_size, replace=False)]
            else:
                background_sample = background_data
            
            if model_type not in self.explainers:
                if not self.create_explainer(model, background_sample):
                    return {}
            
            explainer = self.explainers[model_type]
            shap_values = explainer.shap_values(background_sample)
            
            if isinstance(shap_values, list):
                shap_values = shap_values[1]
            
            global_importance = np.mean(np.abs(shap_values), axis=0)
            
            importance_dict = {}
            for i, feature_name in enumerate(model.feature_names):
                if i < len(global_importance):
                    importance_dict[feature_name] = float(global_importance[i])
            
            return {
                'global_feature_importance': dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)),
                'sample_size': len(background_sample),
                'model_type': model_type
            }
            
        except Exception as e:
            logger.error(f"Global feature importance calculation failed: {e}")
            return {}

    def generate_explanation_report(self, model: BaseMLModel, input_data: np.ndarray) -> Dict[str, Any]:
        explanation = self.explain_prediction(model, input_data)
        global_importance = self.get_global_feature_importance(model)
        
        report = {
            'prediction_explanation': explanation,
            'global_feature_importance': global_importance,
            'model_info': model.get_model_info(),
            'explanation_timestamp': datetime.utcnow().isoformat()
        }
        
        return report

    def clear_explainers(self):
        self.explainers.clear()
        self.background_data.clear()
        logger.info("Cleared all SHAP explainers")

def explain_prediction(model: BaseMLModel, input_data: np.ndarray) -> Dict[str, Any]:
    explainer = SHAPExplainer()
    return explainer.explain_prediction(model, input_data)