"""
Pattern Analyzer Service
Behavioral pattern detection and analysis
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import statistics

from app.core.database import get_db
from app.models.database_models import AttackEvent, AttackerProfile

logger = logging.getLogger(__name__)

class PatternAnalyzer:
    def __init__(self):
        self.behavior_patterns = self._initialize_behavior_patterns()
        self.attack_signatures = self._initialize_attack_signatures()

    def _initialize_behavior_patterns(self) -> Dict[str, Any]:
        return {
            'brute_force': {
                'description': 'Rapid authentication attempts',
                'indicators': ['multiple_failed_logins', 'common_usernames', 'password_spray'],
                'threshold': 5,
                'time_window': 300
            },
            'port_scanning': {
                'description': 'Systematic port scanning',
                'indicators': ['multiple_ports', 'sequential_ports', 'rapid_connections'],
                'threshold': 10,
                'time_window': 600
            },
            'web_scanning': {
                'description': 'Web vulnerability scanning',
                'indicators': ['directory_enumeration', 'parameter_fuzzing', 'header_injection'],
                'threshold': 20,
                'time_window': 900
            },
            'data_exfiltration': {
                'description': 'Attempted data extraction',
                'indicators': ['large_downloads', 'database_queries', 'file_access'],
                'threshold': 3,
                'time_window': 1800
            }
        }

    def _initialize_attack_signatures(self) -> Dict[str, Any]:
        return {
            'sql_injection': {
                'patterns': ['union select', 'select * from', 'insert into', 'drop table'],
                'confidence': 0.85
            },
            'xss_attack': {
                'patterns': ['<script>', 'javascript:', 'onerror=', 'onload='],
                'confidence': 0.80
            },
            'command_injection': {
                'patterns': ['; ls', '| cat', '& dir', '`whoami`'],
                'confidence': 0.75
            },
            'path_traversal': {
                'patterns': ['../etc/passwd', '..\\windows\\', '../../'],
                'confidence': 0.90
            }
        }

    async def analyze_attack_pattern(self, attack_events: List[AttackEvent]) -> Dict[str, Any]:
        try:
            if not attack_events:
                return {'patterns_found': [], 'confidence': 0.0}

            analysis_result = {
                'patterns_found': [],
                'behavioral_analysis': {},
                'temporal_analysis': {},
                'geographical_analysis': {},
                'confidence': 0.0,
                'risk_assessment': {},
                'timestamp': datetime.utcnow().isoformat()
            }

            analysis_result['behavioral_analysis'] = await self._analyze_behavioral_patterns(attack_events)
            analysis_result['temporal_analysis'] = await self._analyze_temporal_patterns(attack_events)
            analysis_result['geographical_analysis'] = await self._analyze_geographical_patterns(attack_events)
            analysis_result['patterns_found'] = await self._detect_attack_patterns(attack_events)
            analysis_result['risk_assessment'] = await self._assess_attack_risk(attack_events)
            analysis_result['confidence'] = self._calculate_analysis_confidence(analysis_result)

            return analysis_result

        except Exception as e:
            logger.error(f"Attack pattern analysis failed: {e}")
            return {'patterns_found': [], 'confidence': 0.0, 'error': str(e)}

    async def _analyze_behavioral_patterns(self, attack_events: List[AttackEvent]) -> Dict[str, Any]:
        behavioral_analysis = {
            'attack_frequency': len(attack_events),
            'unique_attackers': len(set(e.source_ip for e in attack_events)),
            'attack_methods': Counter(e.honeypot_type for e in attack_events),
            'payload_patterns': self._analyze_payload_patterns(attack_events),
            'user_agent_analysis': self._analyze_user_agents(attack_events),
            'detected_behaviors': []
        }

        for pattern_name, pattern_config in self.behavior_patterns.items():
            if self._detect_behavior_pattern(attack_events, pattern_config):
                behavioral_analysis['detected_behaviors'].append({
                    'pattern': pattern_name,
                    'description': pattern_config['description'],
                    'confidence': pattern_config.get('confidence', 0.7)
                })

        return behavioral_analysis

    async def _analyze_temporal_patterns(self, attack_events: List[AttackEvent]) -> Dict[str, Any]:
        if not attack_events:
            return {}

        timestamps = [e.timestamp for e in attack_events]
        timestamps.sort()

        time_differences = []
        for i in range(1, len(timestamps)):
            diff = (timestamps[i] - timestamps[i-1]).total_seconds()
            time_differences.append(diff)

        hourly_distribution = defaultdict(int)
        for event in attack_events:
            hour = event.timestamp.hour
            hourly_distribution[hour] += 1

        return {
            'total_duration_seconds': (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) > 1 else 0,
            'average_interval': statistics.mean(time_differences) if time_differences else 0,
            'burst_detected': self._detect_burst_activity(time_differences),
            'peak_hours': dict(sorted(hourly_distribution.items(), key=lambda x: x[1], reverse=True)[:3]),
            'temporal_clustering': self._analyze_temporal_clustering(timestamps)
        }

    async def _analyze_geographical_patterns(self, attack_events: List[AttackEvent]) -> Dict[str, Any]:
        countries = [e.country for e in attack_events if e.country]
        cities = [e.city for e in attack_events if e.city]

        return {
            'unique_countries': len(set(countries)),
            'unique_cities': len(set(cities)),
            'country_distribution': dict(Counter(countries)),
            'city_distribution': dict(Counter(cities)),
            'geographical_spread': 'global' if len(set(countries)) > 5 else 'regional' if len(set(countries)) > 1 else 'local'
        }

    async def _detect_attack_patterns(self, attack_events: List[AttackEvent]) -> List[Dict[str, Any]]:
        detected_patterns = []

        for event in attack_events:
            for sig_name, signature in self.attack_signatures.items():
                if self._matches_attack_signature(event, signature):
                    detected_patterns.append({
                        'pattern': sig_name,
                        'event_id': event.event_id,
                        'confidence': signature['confidence'],
                        'indicators': self._extract_attack_indicators(event, signature)
                    })

        return detected_patterns

    async def _assess_attack_risk(self, attack_events: List[AttackEvent]) -> Dict[str, Any]:
        risk_factors = {
            'volume_risk': min(len(attack_events) / 100.0, 1.0),
            'sophistication_risk': self._calculate_sophistication_risk(attack_events),
            'persistence_risk': self._calculate_persistence_risk(attack_events),
            'geographical_risk': self._calculate_geographical_risk(attack_events),
            'temporal_risk': self._calculate_temporal_risk(attack_events)
        }

        overall_risk = sum(risk_factors.values()) / len(risk_factors)

        return {
            'overall_risk': overall_risk,
            'risk_level': 'critical' if overall_risk > 0.8 else 'high' if overall_risk > 0.6 else 'medium' if overall_risk > 0.4 else 'low',
            'risk_factors': risk_factors,
            'mitigation_recommendations': self._generate_mitigation_recommendations(risk_factors)
        }

    def _analyze_payload_patterns(self, attack_events: List[AttackEvent]) -> Dict[str, Any]:
        payloads = [e.payload for e in attack_events if e.payload]
        
        return {
            'total_payloads': len(payloads),
            'average_length': statistics.mean(len(p) for p in payloads) if payloads else 0,
            'common_patterns': self._extract_common_patterns(payloads),
            'entropy_analysis': self._analyze_payload_entropy(payloads)
        }

    def _analyze_user_agents(self, attack_events: List[AttackEvent]) -> Dict[str, Any]:
        user_agents = [e.user_agent for e in attack_events if e.user_agent]
        
        suspicious_indicators = ['nmap', 'sqlmap', 'metasploit', 'nikto', 'burp']
        suspicious_count = sum(1 for ua in user_agents if any(indicator in ua.lower() for indicator in suspicious_indicators))
        
        return {
            'total_user_agents': len(user_agents),
            'suspicious_user_agents': suspicious_count,
            'suspicious_ratio': suspicious_count / len(user_agents) if user_agents else 0,
            'common_agents': dict(Counter(user_agents).most_common(5))
        }

    def _detect_behavior_pattern(self, attack_events: List[AttackEvent], pattern_config: Dict[str, Any]) -> bool:
        time_window = pattern_config['time_window']
        threshold = pattern_config['threshold']
        
        recent_events = []
        for event in attack_events:
            if (datetime.utcnow() - event.timestamp).total_seconds() <= time_window:
                recent_events.append(event)
        
        return len(recent_events) >= threshold

    def _detect_burst_activity(self, time_differences: List[float]) -> bool:
        if not time_differences:
            return False
        
        avg_interval = statistics.mean(time_differences)
        burst_threshold = avg_interval * 0.1
        
        burst_count = sum(1 for diff in time_differences if diff < burst_threshold)
        return burst_count > len(time_differences) * 0.3

    def _analyze_temporal_clustering(self, timestamps: List[datetime]) -> str:
        if len(timestamps) < 2:
            return "insufficient_data"
        
        total_duration = (timestamps[-1] - timestamps[0]).total_seconds()
        if total_duration < 300:
            return "highly_clustered"
        elif total_duration < 3600:
            return "moderately_clustered"
        else:
            return "distributed"

    def _matches_attack_signature(self, event: AttackEvent, signature: Dict[str, Any]) -> bool:
        if not event.payload:
            return False
        
        payload_lower = event.payload.lower()
        return any(pattern in payload_lower for pattern in signature['patterns'])

    def _extract_attack_indicators(self, event: AttackEvent, signature: Dict[str, Any]) -> List[str]:
        indicators = []
        payload_lower = event.payload.lower() if event.payload else ""
        
        for pattern in signature['patterns']:
            if pattern in payload_lower:
                indicators.append(pattern)
        
        return indicators

    def _calculate_sophistication_risk(self, attack_events: List[AttackEvent]) -> float:
        sophistication_indicators = 0
        
        for event in attack_events:
            if event.payload and len(event.payload) > 1000:
                sophistication_indicators += 1
            if event.user_agent and any(tool in event.user_agent.lower() for tool in ['nmap', 'sqlmap', 'metasploit']):
                sophistication_indicators += 1
        
        return min(sophistication_indicators / len(attack_events), 1.0) if attack_events else 0.0

    def _calculate_persistence_risk(self, attack_events: List[AttackEvent]) -> float:
        if len(attack_events) < 2:
            return 0.0
        
        timestamps = [e.timestamp for e in attack_events]
        duration = (max(timestamps) - min(timestamps)).total_seconds()
        
        if duration < 3600:
            return min(len(attack_events) / 10.0, 1.0)
        else:
            return min(len(attack_events) / (duration / 3600), 1.0)

    def _calculate_geographical_risk(self, attack_events: List[AttackEvent]) -> float:
        high_risk_countries = ['CN', 'RU', 'KP', 'IR']
        countries = [e.country for e in attack_events if e.country]
        
        if not countries:
            return 0.0
        
        high_risk_count = sum(1 for country in countries if country in high_risk_countries)
        return high_risk_count / len(countries)

    def _calculate_temporal_risk(self, attack_events: List[AttackEvent]) -> float:
        unusual_hours = 0
        for event in attack_events:
            hour = event.timestamp.hour
            if hour < 6 or hour > 22:
                unusual_hours += 1
        
        return unusual_hours / len(attack_events) if attack_events else 0.0

    def _extract_common_patterns(self, payloads: List[str]) -> List[str]:
        if not payloads:
            return []
        
        common_sequences = []
        for payload in payloads[:10]:
            if len(payload) > 10:
                common_sequences.append(payload[:10])
        
        return list(set(common_sequences))[:5]

    def _analyze_payload_entropy(self, payloads: List[str]) -> Dict[str, float]:
        if not payloads:
            return {'average_entropy': 0.0}
        
        entropy_values = []
        for payload in payloads:
            if payload:
                entropy = self._calculate_entropy(payload)
                entropy_values.append(entropy)
        
        return {
            'average_entropy': statistics.mean(entropy_values) if entropy_values else 0.0,
            'max_entropy': max(entropy_values) if entropy_values else 0.0
        }

    def _calculate_entropy(self, text: str) -> float:
        import math
        from collections import Counter
        
        if not text:
            return 0.0
        
        counter = Counter(text)
        text_length = len(text)
        entropy = 0.0
        
        for count in counter.values():
            p_x = count / text_length
            entropy += -p_x * math.log2(p_x)
        
        return entropy

    def _generate_mitigation_recommendations(self, risk_factors: Dict[str, float]) -> List[str]:
        recommendations = []
        
        if risk_factors.get('volume_risk', 0) > 0.7:
            recommendations.append("Implement aggressive rate limiting for source IPs")
        
        if risk_factors.get('sophistication_risk', 0) > 0.6:
            recommendations.append("Enable advanced threat detection rules")
        
        if risk_factors.get('persistence_risk', 0) > 0.5:
            recommendations.append("Consider IP blocking for persistent attackers")
        
        if risk_factors.get('geographical_risk', 0) > 0.4:
            recommendations.append("Review geographical access patterns")
        
        return recommendations

    def _calculate_analysis_confidence(self, analysis_result: Dict[str, Any]) -> float:
        confidence_factors = []
        
        if analysis_result['patterns_found']:
            confidence_factors.append(0.8)
        
        if analysis_result['behavioral_analysis'].get('detected_behaviors'):
            confidence_factors.append(0.7)
        
        if analysis_result['temporal_analysis'].get('burst_detected'):
            confidence_factors.append(0.6)
        
        if analysis_result['risk_assessment'].get('overall_risk', 0) > 0.5:
            confidence_factors.append(0.5)
        
        return statistics.mean(confidence_factors) if confidence_factors else 0.3

    async def detect_behavioral_patterns(self, attacker_ip: str, time_window_hours: int = 24) -> Dict[str, Any]:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            time_threshold = datetime.utcnow() - timedelta(hours=time_window_hours)
            
            events = db.query(AttackEvent).filter(
                AttackEvent.source_ip == attacker_ip,
                AttackEvent.timestamp >= time_threshold
            ).order_by(AttackEvent.timestamp.asc()).all()
            
            db.close()
            
            return await self.analyze_attack_pattern(events)
            
        except Exception as e:
            logger.error(f"Behavioral pattern detection failed for {attacker_ip}: {e}")
            return {'patterns_found': [], 'confidence': 0.0}

pattern_analyzer = PatternAnalyzer()

async def analyze_attack_pattern(attack_events: List[AttackEvent]) -> Dict[str, Any]:
    return await pattern_analyzer.analyze_attack_pattern(attack_events)

async def detect_behavioral_patterns(attacker_ip: str, time_window_hours: int = 24) -> Dict[str, Any]:
    return await pattern_analyzer.detect_behavioral_patterns(attacker_ip, time_window_hours)