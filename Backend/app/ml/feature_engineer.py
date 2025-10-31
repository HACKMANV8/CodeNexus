"""
Feature Engineering for ML Models
Extracts and transforms features from raw attack data
"""

import logging
import numpy as np
from typing import Dict, Any, List, Optional
from datetime import datetime
import re
import hashlib
from urllib.parse import urlparse
import tldextract

logger = logging.getLogger(__name__)

class FeatureEngineer:
    def __init__(self):
        self.suspicious_user_agents = [
            'nmap', 'sqlmap', 'metasploit', 'nikto', 'burp', 'hydra',
            'wget', 'curl', 'python', 'java', 'gobuster', 'dirb'
        ]
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
        self.high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'BR', 'IN']

    def extract_url_features(self, url: str) -> Dict[str, Any]:
        features = {}
        
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            features['url_length'] = len(url)
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_slashes'] = url.count('/')
            features['num_question_marks'] = url.count('?')
            features['num_equals'] = url.count('=')
            features['num_ampersands'] = url.count('&')
            features['num_digits'] = sum(c.isdigit() for c in url)
            features['num_parameters'] = len(parsed.query.split('&')) if parsed.query else 0
            
            features['has_https'] = 1 if parsed.scheme == 'https' else 0
            features['has_ip_address'] = 1 if self._contains_ip_address(url) else 0
            features['suspicious_tld'] = 1 if extracted.suffix in self.suspicious_tlds else 0
            features['num_subdomains'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            
            features['entropy'] = self._calculate_entropy(url)
            features['domain_length'] = len(extracted.domain)
            features['tld_length'] = len(extracted.suffix)
            
            features['is_shortened'] = 1 if self._is_shortened_url(url) else 0
            features['has_redirect'] = 1 if '//' in url.split('://', 1)[-1] else 0
            
        except Exception as e:
            logger.error(f"URL feature extraction failed: {e}")
            features = self._get_default_url_features()
        
        return features

    def extract_behavioral_features(self, attack_event: Dict[str, Any]) -> Dict[str, Any]:
        features = {}
        
        try:
            features['honeypot_type_encoded'] = self._encode_honeypot_type(attack_event.get('honeypot_type'))
            features['payload_length'] = len(attack_event.get('payload', ''))
            features['suspicious_user_agent'] = self._is_suspicious_user_agent(attack_event.get('user_agent'))
            features['unusual_working_hours'] = self._is_unusual_working_hours(attack_event.get('timestamp'))
            features['geo_risk_score'] = self._calculate_geo_risk(attack_event.get('country'))
            features['authentication_attempts'] = attack_event.get('auth_attempts', 0)
            features['request_frequency'] = self._calculate_request_frequency(attack_event)
            features['brute_force_pattern'] = self._detect_brute_force_pattern(attack_event)
            features['scanning_pattern'] = self._detect_scanning_pattern(attack_event)
            features['reconnaissance_score'] = self._calculate_reconnaissance_score(attack_event)
            
            features['source_ip_entropy'] = self._calculate_ip_entropy(attack_event.get('source_ip', ''))
            features['destination_port'] = attack_event.get('destination_port', 0)
            features['is_privileged_port'] = 1 if features['destination_port'] < 1024 else 0
            
            features['session_duration'] = self._calculate_session_duration(attack_event)
            features['request_complexity'] = self._calculate_request_complexity(attack_event)
            
        except Exception as e:
            logger.error(f"Behavioral feature extraction failed: {e}")
            features = self._get_default_behavioral_features()
        
        return features

    def extract_threat_features(self, attack_event: Dict[str, Any]) -> Dict[str, Any]:
        features = {}
        
        try:
            behavioral_features = self.extract_behavioral_features(attack_event)
            features.update(behavioral_features)
            
            features['threat_intel_match'] = self._check_threat_intelligence(attack_event)
            features['previous_attacks_count'] = self._get_previous_attacks_count(attack_event)
            features['attack_variety'] = self._calculate_attack_variety(attack_event)
            features['temporal_pattern'] = self._analyze_temporal_pattern(attack_event)
            features['payload_entropy'] = self._calculate_entropy(attack_event.get('payload', ''))
            features['sql_injection_indicators'] = self._detect_sql_injection(attack_event)
            features['xss_indicators'] = self._detect_xss(attack_event)
            features['command_injection_indicators'] = self._detect_command_injection(attack_event)
            
            features['risk_score_combined'] = self._combine_risk_scores(features)
            features['anomaly_score'] = self._calculate_anomaly_score(features)
            
        except Exception as e:
            logger.error(f"Threat feature extraction failed: {e}")
            features = self._get_default_threat_features()
        
        return features

    def _contains_ip_address(self, url: str) -> bool:
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.search(ip_pattern, url))

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        
        entropy = 0.0
        for char in set(text):
            p_x = float(text.count(char)) / len(text)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        return entropy

    def _is_shortened_url(self, url: str) -> bool:
        shortened_domains = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly']
        parsed = urlparse(url)
        return any(domain in parsed.netloc for domain in shortened_domains)

    def _encode_honeypot_type(self, honeypot_type: str) -> int:
        encoding = {'ssh': 0, 'web': 1, 'ftp': 2, 'url_trap': 3}
        return encoding.get(honeypot_type, -1)

    def _is_suspicious_user_agent(self, user_agent: Optional[str]) -> int:
        if not user_agent:
            return 0
        
        user_agent_lower = user_agent.lower()
        return 1 if any(agent in user_agent_lower for agent in self.suspicious_user_agents) else 0

    def _is_unusual_working_hours(self, timestamp: Any) -> int:
        try:
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = timestamp
            
            hour = dt.hour
            return 1 if hour < 6 or hour > 22 else 0
            
        except:
            return 0

    def _calculate_geo_risk(self, country: Optional[str]) -> float:
        if not country:
            return 0.0
        
        return 1.0 if country in self.high_risk_countries else 0.0

    def _calculate_request_frequency(self, attack_event: Dict[str, Any]) -> float:
        return 0.0

    def _detect_brute_force_pattern(self, attack_event: Dict[str, Any]) -> int:
        honeypot_type = attack_event.get('honeypot_type')
        payload = attack_event.get('payload', '')
        
        if honeypot_type == 'ssh' and 'password' in payload.lower():
            return 1
        
        return 0

    def _detect_scanning_pattern(self, attack_event: Dict[str, Any]) -> int:
        user_agent = attack_event.get('user_agent', '').lower()
        if any(scanner in user_agent for scanner in ['nmap', 'nikto', 'gobuster']):
            return 1
        
        return 0

    def _calculate_reconnaissance_score(self, attack_event: Dict[str, Any]) -> float:
        score = 0.0
        
        if self._detect_scanning_pattern(attack_event) == 1:
            score += 0.7
        
        if attack_event.get('honeypot_type') == 'web' and attack_event.get('method') == 'GET':
            score += 0.3
        
        return min(score, 1.0)

    def _calculate_ip_entropy(self, ip_address: str) -> float:
        return self._calculate_entropy(ip_address)

    def _calculate_session_duration(self, attack_event: Dict[str, Any]) -> float:
        return 0.0

    def _calculate_request_complexity(self, attack_event: Dict[str, Any]) -> float:
        payload = attack_event.get('payload', '')
        headers = attack_event.get('headers', {})
        
        complexity = len(payload) / 1000
        complexity += len(headers) * 0.1
        
        return min(complexity, 1.0)

    def _check_threat_intelligence(self, attack_event: Dict[str, Any]) -> float:
        return 0.0

    def _get_previous_attacks_count(self, attack_event: Dict[str, Any]) -> int:
        return 0

    def _calculate_attack_variety(self, attack_event: Dict[str, Any]) -> float:
        return 0.0

    def _analyze_temporal_pattern(self, attack_event: Dict[str, Any]) -> float:
        return 0.0

    def _detect_sql_injection(self, attack_event: Dict[str, Any]) -> int:
        payload = str(attack_event.get('payload', '')).lower()
        sql_patterns = ['union select', 'select * from', 'insert into', 'drop table', 'or 1=1']
        
        return 1 if any(pattern in payload for pattern in sql_patterns) else 0

    def _detect_xss(self, attack_event: Dict[str, Any]) -> int:
        payload = str(attack_event.get('payload', '')).lower()
        xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=']
        
        return 1 if any(pattern in payload for pattern in xss_patterns) else 0

    def _detect_command_injection(self, attack_event: Dict[str, Any]) -> int:
        payload = str(attack_event.get('payload', '')).lower()
        cmd_patterns = ['; ls', '| cat', '& dir', '`whoami`', '$(id)']
        
        return 1 if any(pattern in payload for pattern in cmd_patterns) else 0

    def _combine_risk_scores(self, features: Dict[str, Any]) -> float:
        risk_score = 0.0
        
        important_features = [
            'suspicious_user_agent',
            'brute_force_pattern', 
            'scanning_pattern',
            'sql_injection_indicators',
            'xss_indicators',
            'geo_risk_score'
        ]
        
        for feature in important_features:
            risk_score += features.get(feature, 0) * 0.15
        
        return min(risk_score, 1.0)

    def _calculate_anomaly_score(self, features: Dict[str, Any]) -> float:
        anomaly_indicators = [
            'unusual_working_hours',
            'high_entropy_payload',
            'suspicious_user_agent',
            'brute_force_pattern'
        ]
        
        anomaly_count = sum(1 for indicator in anomaly_indicators if features.get(indicator, 0) > 0)
        return anomaly_count / len(anomaly_indicators)

    def _get_default_url_features(self) -> Dict[str, Any]:
        return {
            'url_length': 0,
            'num_dots': 0,
            'num_hyphens': 0,
            'num_underscores': 0,
            'num_slashes': 0,
            'num_question_marks': 0,
            'num_equals': 0,
            'num_ampersands': 0,
            'num_digits': 0,
            'num_parameters': 0,
            'has_https': 0,
            'has_ip_address': 0,
            'suspicious_tld': 0,
            'num_subdomains': 0,
            'entropy': 0.0,
            'domain_length': 0,
            'tld_length': 0,
            'is_shortened': 0,
            'has_redirect': 0
        }

    def _get_default_behavioral_features(self) -> Dict[str, Any]:
        return {
            'honeypot_type_encoded': -1,
            'payload_length': 0,
            'suspicious_user_agent': 0,
            'unusual_working_hours': 0,
            'geo_risk_score': 0.0,
            'authentication_attempts': 0,
            'request_frequency': 0.0,
            'brute_force_pattern': 0,
            'scanning_pattern': 0,
            'reconnaissance_score': 0.0,
            'source_ip_entropy': 0.0,
            'destination_port': 0,
            'is_privileged_port': 0,
            'session_duration': 0.0,
            'request_complexity': 0.0
        }

    def _get_default_threat_features(self) -> Dict[str, Any]:
        base_features = self._get_default_behavioral_features()
        
        threat_features = {
            'threat_intel_match': 0.0,
            'previous_attacks_count': 0,
            'attack_variety': 0.0,
            'temporal_pattern': 0.0,
            'payload_entropy': 0.0,
            'sql_injection_indicators': 0,
            'xss_indicators': 0,
            'command_injection_indicators': 0,
            'risk_score_combined': 0.0,
            'anomaly_score': 0.0
        }
        
        base_features.update(threat_features)
        return base_features

def extract_features(feature_type: str, data: Any) -> Dict[str, Any]:
    engineer = FeatureEngineer()
    
    if feature_type == 'url':
        return engineer.extract_url_features(data)
    elif feature_type == 'behavioral':
        return engineer.extract_behavioral_features(data)
    elif feature_type == 'threat':
        return engineer.extract_threat_features(data)
    else:
        logger.warning(f"Unknown feature type: {feature_type}")
        return {}