"""
Attack Predictor Service
Predicts future attacks based on historical patterns
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import numpy as np
from collections import defaultdict, Counter

from app.core.database import get_db
from app.models.database_models import AttackEvent, AttackerProfile

logger = logging.getLogger(__name__)

class AttackPredictor:
    def __init__(self):
        self.prediction_horizon = 24
        self.confidence_threshold = 0.7
        self.pattern_weights = self._initialize_pattern_weights()

    def _initialize_pattern_weights(self) -> Dict[str, float]:
        return {
            'temporal_pattern': 0.3,
            'behavioral_pattern': 0.4,
            'geographical_pattern': 0.2,
            'threat_intel': 0.1
        }

    async def predict_next_attack(self, attacker_ip: str) -> Dict[str, Any]:
        try:
            historical_data = await self._get_historical_data(attacker_ip)
            
            if not historical_data:
                return self._get_default_prediction(attacker_ip)

            prediction_result = {
                'attacker_ip': attacker_ip,
                'prediction_timestamp': datetime.utcnow().isoformat(),
                'prediction_horizon_hours': self.prediction_horizon,
                'next_attack_likelihood': 0.0,
                'predicted_time_window': {},
                'confidence': 0.0,
                'risk_factors': [],
                'recommendations': []
            }

            temporal_analysis = await self._analyze_temporal_patterns(historical_data)
            behavioral_analysis = await self._analyze_behavioral_patterns(historical_data)
            geographical_analysis = await self._analyze_geographical_patterns(historical_data)
            threat_analysis = await self._analyze_threat_intelligence(attacker_ip)

            likelihood_factors = {
                'temporal': temporal_analysis.get('likelihood', 0.0) * self.pattern_weights['temporal_pattern'],
                'behavioral': behavioral_analysis.get('likelihood', 0.0) * self.pattern_weights['behavioral_pattern'],
                'geographical': geographical_analysis.get('likelihood', 0.0) * self.pattern_weights['geographical_pattern'],
                'threat_intel': threat_analysis.get('likelihood', 0.0) * self.pattern_weights['threat_intel']
            }

            prediction_result['next_attack_likelihood'] = sum(likelihood_factors.values())
            prediction_result['confidence'] = self._calculate_prediction_confidence(likelihood_factors)
            prediction_result['predicted_time_window'] = self._predict_time_window(temporal_analysis)
            prediction_result['risk_factors'] = self._identify_risk_factors(likelihood_factors)
            prediction_result['recommendations'] = self._generate_recommendations(prediction_result)

            return prediction_result

        except Exception as e:
            logger.error(f"Attack prediction failed for {attacker_ip}: {e}")
            return self._get_default_prediction(attacker_ip)

    async def _get_historical_data(self, attacker_ip: str) -> List[AttackEvent]:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            time_threshold = datetime.utcnow() - timedelta(days=7)
            
            events = db.query(AttackEvent).filter(
                AttackEvent.source_ip == attacker_ip,
                AttackEvent.timestamp >= time_threshold
            ).order_by(AttackEvent.timestamp.asc()).all()
            
            db.close()
            return events
            
        except Exception as e:
            logger.error(f"Failed to get historical data for {attacker_ip}: {e}")
            return []

    async def _analyze_temporal_patterns(self, historical_data: List[AttackEvent]) -> Dict[str, Any]:
        if not historical_data:
            return {'likelihood': 0.0, 'pattern': 'no_data'}

        timestamps = [event.timestamp for event in historical_data]
        hourly_distribution = defaultdict(int)
        daily_distribution = defaultdict(int)

        for timestamp in timestamps:
            hourly_distribution[timestamp.hour] += 1
            daily_distribution[timestamp.weekday()] += 1

        current_hour = datetime.utcnow().hour
        current_day = datetime.utcnow().weekday()

        hour_likelihood = hourly_distribution[current_hour] / max(sum(hourly_distribution.values()), 1)
        day_likelihood = daily_distribution[current_day] / max(sum(daily_distribution.values()), 1)

        temporal_likelihood = (hour_likelihood + day_likelihood) / 2

        return {
            'likelihood': temporal_likelihood,
            'pattern': 'consistent' if temporal_likelihood > 0.3 else 'random',
            'peak_hours': dict(sorted(hourly_distribution.items(), key=lambda x: x[1], reverse=True)[:3]),
            'active_days': dict(sorted(daily_distribution.items(), key=lambda x: x[1], reverse=True)[:3])
        }

    async def _analyze_behavioral_patterns(self, historical_data: List[AttackEvent]) -> Dict[str, Any]:
        if not historical_data:
            return {'likelihood': 0.0, 'pattern': 'no_data'}

        attack_types = [event.honeypot_type for event in historical_data]
        type_counter = Counter(attack_types)

        most_common_type = type_counter.most_common(1)[0][0] if type_counter else 'unknown'
        behavioral_consistency = type_counter[most_common_type] / len(historical_data)

        recent_events = [e for e in historical_data if (datetime.utcnow() - e.timestamp).total_seconds() < 3600]
        recent_activity = len(recent_events) / 10.0

        behavioral_likelihood = (behavioral_consistency + min(recent_activity, 1.0)) / 2

        return {
            'likelihood': behavioral_likelihood,
            'pattern': most_common_type,
            'consistency': behavioral_consistency,
            'recent_activity': len(recent_events)
        }

    async def _analyze_geographical_patterns(self, historical_data: List[AttackEvent]) -> Dict[str, Any]:
        if not historical_data:
            return {'likelihood': 0.0, 'pattern': 'no_data'}

        countries = [event.country for event in historical_data if event.country]
        if not countries:
            return {'likelihood': 0.0, 'pattern': 'unknown'}

        country_counter = Counter(countries)
        geographical_consistency = len(set(countries)) == 1

        high_risk_countries = ['CN', 'RU', 'KP', 'IR']
        high_risk_ratio = sum(1 for country in countries if country in high_risk_countries) / len(countries)

        geographical_likelihood = (geographical_consistency * 0.5) + (high_risk_ratio * 0.5)

        return {
            'likelihood': geographical_likelihood,
            'pattern': 'stable' if geographical_consistency else 'distributed',
            'primary_country': country_counter.most_common(1)[0][0] if country_counter else 'unknown',
            'high_risk_ratio': high_risk_ratio
        }

    async def _analyze_threat_intelligence(self, attacker_ip: str) -> Dict[str, Any]:
        try:
            from app.services.threat_intel import check_threat_intel
            
            threat_data = await check_threat_intel(attacker_ip, 'ip')
            threat_score = threat_data.get('threat_score', 0.0)
            
            return {
                'likelihood': threat_score,
                'threat_level': 'high' if threat_score > 0.7 else 'medium' if threat_score > 0.3 else 'low',
                'sources_checked': threat_data.get('sources_checked', [])
            }
            
        except Exception as e:
            logger.error(f"Threat intelligence analysis failed for {attacker_ip}: {e}")
            return {'likelihood': 0.0, 'threat_level': 'unknown'}

    def _predict_time_window(self, temporal_analysis: Dict[str, Any]) -> Dict[str, Any]:
        peak_hours = temporal_analysis.get('peak_hours', {})
        
        if not peak_hours:
            return {
                'start_hour': 0,
                'end_hour': 23,
                'confidence': 0.1
            }
        
        most_likely_hours = list(peak_hours.keys())[:2]
        if len(most_likely_hours) == 1:
            start_hour = max(0, most_likely_hours[0] - 2)
            end_hour = min(23, most_likely_hours[0] + 2)
        else:
            start_hour = min(most_likely_hours)
            end_hour = max(most_likely_hours)
        
        return {
            'start_hour': start_hour,
            'end_hour': end_hour,
            'confidence': temporal_analysis.get('likelihood', 0.0)
        }

    def _calculate_prediction_confidence(self, likelihood_factors: Dict[str, float]) -> float:
        total_likelihood = sum(likelihood_factors.values())
        factor_count = len([v for v in likelihood_factors.values() if v > 0])
        
        if factor_count == 0:
            return 0.0
        
        base_confidence = total_likelihood
        consistency_bonus = factor_count / len(likelihood_factors) * 0.3
        
        return min(base_confidence + consistency_bonus, 1.0)

    def _identify_risk_factors(self, likelihood_factors: Dict[str, float]) -> List[str]:
        risk_factors = []
        
        if likelihood_factors.get('behavioral', 0) > 0.6:
            risk_factors.append('consistent_attack_pattern')
        
        if likelihood_factors.get('temporal', 0) > 0.5:
            risk_factors.append('predictable_timing')
        
        if likelihood_factors.get('geographical', 0) > 0.4:
            risk_factors.append('high_risk_geography')
        
        if likelihood_factors.get('threat_intel', 0) > 0.3:
            risk_factors.append('known_threat_actor')
        
        return risk_factors

    def _generate_recommendations(self, prediction_result: Dict[str, Any]) -> List[str]:
        recommendations = []
        likelihood = prediction_result['next_attack_likelihood']
        
        if likelihood > 0.8:
            recommendations.extend([
                "Implement immediate IP blocking",
                "Increase monitoring frequency",
                "Prepare incident response team"
            ])
        elif likelihood > 0.6:
            recommendations.extend([
                "Enable enhanced logging",
                "Review firewall rules",
                "Monitor for specific attack patterns"
            ])
        elif likelihood > 0.4:
            recommendations.extend([
                "Watch for activity during predicted time window",
                "Update threat intelligence",
                "Review recent attack patterns"
            ])
        else:
            recommendations.append("Continue standard monitoring")
        
        return recommendations

    def _get_default_prediction(self, attacker_ip: str) -> Dict[str, Any]:
        return {
            'attacker_ip': attacker_ip,
            'prediction_timestamp': datetime.utcnow().isoformat(),
            'prediction_horizon_hours': self.prediction_horizon,
            'next_attack_likelihood': 0.1,
            'predicted_time_window': {'start_hour': 0, 'end_hour': 23, 'confidence': 0.1},
            'confidence': 0.1,
            'risk_factors': ['insufficient_data'],
            'recommendations': ['Collect more attack data for accurate prediction'],
            'fallback': True
        }

    async def calculate_attack_risk(self, attacker_ip: str) -> Dict[str, Any]:
        prediction = await self.predict_next_attack(attacker_ip)
        
        likelihood = prediction['next_attack_likelihood']
        confidence = prediction['confidence']
        
        risk_score = likelihood * confidence
        
        return {
            'attacker_ip': attacker_ip,
            'risk_score': risk_score,
            'risk_level': 'critical' if risk_score > 0.8 else 'high' if risk_score > 0.6 else 'medium' if risk_score > 0.4 else 'low',
            'likelihood': likelihood,
            'confidence': confidence,
            'factors_considered': len(prediction['risk_factors']),
            'timestamp': datetime.utcnow().isoformat()
        }

    def get_service_status(self) -> Dict[str, Any]:
        return {
            'status': 'active',
            'prediction_horizon_hours': self.prediction_horizon,
            'confidence_threshold': self.confidence_threshold,
            'pattern_weights': self.pattern_weights
        }

attack_predictor = AttackPredictor()

async def predict_next_attack(attacker_ip: str) -> Dict[str, Any]:
    return await attack_predictor.predict_next_attack(attacker_ip)

async def calculate_attack_risk(attacker_ip: str) -> Dict[str, Any]:
    return await attack_predictor.calculate_attack_risk(attacker_ip)