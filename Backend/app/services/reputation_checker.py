"""
Reputation Checker Service
IP and domain reputation analysis
"""

import logging
import aiohttp
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.core.cache import cache_manager
from app.services.threat_intel import threat_intel_service
from app.services.whois_client import whois_client

logger = logging.getLogger(__name__)

class ReputationChecker:
    def __init__(self):
        self.cache = cache_manager
        self.cache_ttl = 7200
        self.reputation_sources = self._initialize_reputation_sources()
        self.reputation_thresholds = {
            'high_risk': 0.7,
            'medium_risk': 0.4,
            'low_risk': 0.1
        }

    def _initialize_reputation_sources(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'Threat Intelligence',
                'weight': 0.4,
                'enabled': True
            },
            {
                'name': 'WHOIS Analysis',
                'weight': 0.3,
                'enabled': True
            },
            {
                'name': 'GeoIP Risk',
                'weight': 0.2,
                'enabled': True
            },
            {
                'name': 'Historical Behavior',
                'weight': 0.1,
                'enabled': True
            }
        ]

    async def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        cache_key = f"reputation:ip:{ip_address}"
        
        cached_result = self.cache.get(cache_key)
        if cached_result:
            return cached_result

        try:
            reputation_scores = {}
            source_details = {}

            for source in self.reputation_sources:
                if source['enabled']:
                    source_result = await self._check_reputation_source(source, ip_address, 'ip')
                    reputation_scores[source['name']] = source_result.get('score', 0.0)
                    source_details[source['name']] = source_result

            overall_score = self._calculate_overall_reputation(reputation_scores)
            reputation_level = self._determine_reputation_level(overall_score)

            result = {
                'ip_address': ip_address,
                'reputation_score': overall_score,
                'reputation_level': reputation_level,
                'source_scores': reputation_scores,
                'source_details': source_details,
                'risk_factors': self._identify_risk_factors(source_details),
                'recommendations': self._generate_reputation_recommendations(overall_score, reputation_level),
                'last_updated': datetime.utcnow().isoformat()
            }

            self.cache.set(cache_key, result, self.cache_ttl)
            return result

        except Exception as e:
            logger.error(f"IP reputation check failed for {ip_address}: {e}")
            return self._get_default_reputation_result(ip_address, 'ip')

    async def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        cache_key = f"reputation:domain:{domain}"
        
        cached_result = self.cache.get(cache_key)
        if cached_result:
            return cached_result

        try:
            reputation_scores = {}
            source_details = {}

            for source in self.reputation_sources:
                if source['enabled']:
                    source_result = await self._check_reputation_source(source, domain, 'domain')
                    reputation_scores[source['name']] = source_result.get('score', 0.0)
                    source_details[source['name']] = source_result

            overall_score = self._calculate_overall_reputation(reputation_scores)
            reputation_level = self._determine_reputation_level(overall_score)

            result = {
                'domain': domain,
                'reputation_score': overall_score,
                'reputation_level': reputation_level,
                'source_scores': reputation_scores,
                'source_details': source_details,
                'risk_factors': self._identify_risk_factors(source_details),
                'recommendations': self._generate_reputation_recommendations(overall_score, reputation_level),
                'last_updated': datetime.utcnow().isoformat()
            }

            self.cache.set(cache_key, result, self.cache_ttl)
            return result

        except Exception as e:
            logger.error(f"Domain reputation check failed for {domain}: {e}")
            return self._get_default_reputation_result(domain, 'domain')

    async def _check_reputation_source(self, source: Dict[str, Any], indicator: str, indicator_type: str) -> Dict[str, Any]:
        try:
            if source['name'] == 'Threat Intelligence':
                return await self._check_threat_intel_source(indicator, indicator_type)
            elif source['name'] == 'WHOIS Analysis':
                return await self._check_whois_source(indicator, indicator_type)
            elif source['name'] == 'GeoIP Risk':
                return await self._check_geoip_source(indicator, indicator_type)
            elif source['name'] == 'Historical Behavior':
                return await self._check_historical_source(indicator, indicator_type)
            else:
                return {'score': 0.0, 'error': 'Unknown source'}
                
        except Exception as e:
            logger.error(f"Reputation source {source['name']} check failed: {e}")
            return {'score': 0.0, 'error': str(e)}

    async def _check_threat_intel_source(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        try:
            threat_data = await threat_intel_service.check_threat_intel(indicator, indicator_type)
            threat_score = threat_data.get('threat_score', 0.0)
            
            return {
                'score': threat_score,
                'malicious_count': threat_data.get('malicious_count', 0),
                'suspicious_count': threat_data.get('suspicious_count', 0),
                'sources_checked': threat_data.get('sources_checked', [])
            }
        except Exception as e:
            logger.error(f"Threat intelligence reputation check failed: {e}")
            return {'score': 0.0, 'error': str(e)}

    async def _check_whois_source(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        try:
            whois_data = await whois_client.get_whois_info(indicator)
            risk_score = whois_data.get('risk_score', 0.0)
            is_suspicious = whois_data.get('is_suspicious', False)
            
            final_score = risk_score * 0.8 + (0.2 if is_suspicious else 0.0)
            
            return {
                'score': final_score,
                'risk_score': risk_score,
                'is_suspicious': is_suspicious,
                'domain_age': whois_data.get('creation_date')
            }
        except Exception as e:
            logger.error(f"WHOIS reputation check failed: {e}")
            return {'score': 0.0, 'error': str(e)}

    async def _check_geoip_source(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        try:
            from app.services.geoip import geoip_service
            
            if indicator_type == 'ip':
                geo_data = await geoip_service.get_geoip_data(indicator)
                risk_score = geo_data.get('risk_score', 0.0)
                is_high_risk = geo_data.get('is_high_risk', False)
                
                final_score = risk_score * 0.7 + (0.3 if is_high_risk else 0.0)
                
                return {
                    'score': final_score,
                    'risk_score': risk_score,
                    'is_high_risk': is_high_risk,
                    'country': geo_data.get('country_code')
                }
            else:
                return {'score': 0.0, 'note': 'GeoIP not applicable for domains'}
                
        except Exception as e:
            logger.error(f"GeoIP reputation check failed: {e}")
            return {'score': 0.0, 'error': str(e)}

    async def _check_historical_source(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            time_threshold = datetime.utcnow() - timedelta(days=30)
            
            if indicator_type == 'ip':
                attack_count = db.query(AttackEvent).filter(
                    AttackEvent.source_ip == indicator,
                    AttackEvent.timestamp >= time_threshold
                ).count()
                
                malicious_count = db.query(AttackEvent).filter(
                    AttackEvent.source_ip == indicator,
                    AttackEvent.timestamp >= time_threshold,
                    AttackEvent.is_malicious == True
                ).count()
            else:
                attack_count = 0
                malicious_count = 0
            
            db.close()
            
            if attack_count == 0:
                historical_score = 0.0
            else:
                malicious_ratio = malicious_count / attack_count
                activity_level = min(attack_count / 100.0, 1.0)
                historical_score = (malicious_ratio * 0.7) + (activity_level * 0.3)
            
            return {
                'score': historical_score,
                'attack_count': attack_count,
                'malicious_count': malicious_count,
                'malicious_ratio': malicious_count / attack_count if attack_count > 0 else 0.0
            }
            
        except Exception as e:
            logger.error(f"Historical reputation check failed: {e}")
            return {'score': 0.0, 'error': str(e)}

    def _calculate_overall_reputation(self, reputation_scores: Dict[str, float]) -> float:
        total_weight = 0.0
        weighted_score = 0.0
        
        for source_name, score in reputation_scores.items():
            source_config = next((s for s in self.reputation_sources if s['name'] == source_name), None)
            if source_config and source_config['enabled']:
                weight = source_config['weight']
                total_weight += weight
                weighted_score += score * weight
        
        return weighted_score / total_weight if total_weight > 0 else 0.0

    def _determine_reputation_level(self, reputation_score: float) -> str:
        if reputation_score >= self.reputation_thresholds['high_risk']:
            return 'high_risk'
        elif reputation_score >= self.reputation_thresholds['medium_risk']:
            return 'medium_risk'
        elif reputation_score >= self.reputation_thresholds['low_risk']:
            return 'low_risk'
        else:
            return 'trusted'

    def _identify_risk_factors(self, source_details: Dict[str, Any]) -> List[str]:
        risk_factors = []
        
        for source_name, details in source_details.items():
            score = details.get('score', 0.0)
            
            if score > 0.7:
                risk_factors.append(f"high_risk_{source_name.lower().replace(' ', '_')}")
            elif score > 0.4:
                risk_factors.append(f"medium_risk_{source_name.lower().replace(' ', '_')}")
            
            if details.get('is_suspicious'):
                risk_factors.append(f"suspicious_{source_name.lower().replace(' ', '_')}")
            
            if details.get('is_high_risk'):
                risk_factors.append(f"high_risk_geography")
        
        return risk_factors

    def _generate_reputation_recommendations(self, reputation_score: float, reputation_level: str) -> List[str]:
        recommendations = []
        
        if reputation_level == 'high_risk':
            recommendations.extend([
                "Consider immediate blocking",
                "Increase monitoring frequency",
                "Review all related activity"
            ])
        elif reputation_level == 'medium_risk':
            recommendations.extend([
                "Monitor for suspicious activity",
                "Implement temporary restrictions if needed",
                "Update threat intelligence"
            ])
        elif reputation_level == 'low_risk':
            recommendations.extend([
                "Continue standard monitoring",
                "Watch for behavior changes"
            ])
        else:
            recommendations.append("No special actions needed")
        
        return recommendations

    def _get_default_reputation_result(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        base_result = {
            'reputation_score': 0.5,
            'reputation_level': 'unknown',
            'source_scores': {},
            'source_details': {},
            'risk_factors': ['reputation_check_failed'],
            'recommendations': ['Use caution - reputation check incomplete'],
            'last_updated': datetime.utcnow().isoformat()
        }
        
        if indicator_type == 'ip':
            base_result['ip_address'] = indicator
        else:
            base_result['domain'] = indicator
        
        return base_result

    async def batch_check_ip_reputation(self, ip_addresses: List[str]) -> Dict[str, Dict[str, Any]]:
        results = {}
        
        for ip in ip_addresses:
            results[ip] = await self.check_ip_reputation(ip)
        
        return results

    async def batch_check_domain_reputation(self, domains: List[str]) -> Dict[str, Dict[str, Any]]:
        results = {}
        
        for domain in domains:
            results[domain] = await self.check_domain_reputation(domain)
        
        return results

    def get_service_status(self) -> Dict[str, Any]:
        enabled_sources = [s for s in self.reputation_sources if s['enabled']]
        
        return {
            'status': 'active',
            'enabled_sources': len(enabled_sources),
            'total_sources': len(self.reputation_sources),
            'cache_ttl': self.cache_ttl,
            'reputation_thresholds': self.reputation_thresholds
        }

reputation_checker = ReputationChecker()

async def check_ip_reputation(ip_address: str) -> Dict[str, Any]:
    return await reputation_checker.check_ip_reputation(ip_address)

async def check_domain_reputation(domain: str) -> Dict[str, Any]:
    return await reputation_checker.check_domain_reputation(domain)