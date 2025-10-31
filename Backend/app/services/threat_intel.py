"""
Threat Intelligence Service
IOC feeds and threat data integration
"""

import logging
import aiohttp
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

from app.core.config import settings
from app.core.cache import cache_manager
from app.models.database_models import ThreatIntelligence

logger = logging.getLogger(__name__)

class ThreatIntelService:
    def __init__(self):
        self.cache = cache_manager
        self.cache_ttl = 1800
        self.threat_feeds = self._initialize_threat_feeds()
        self.session = None

    def _initialize_threat_feeds(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'AlienVault OTX',
                'url': 'https://otx.alienvault.com/api/v1/indicators/ip/{indicator}/general',
                'enabled': True,
                'api_key_required': True
            },
            {
                'name': 'AbuseIPDB',
                'url': 'https://api.abuseipdb.com/api/v2/check',
                'enabled': True,
                'api_key_required': True
            },
            {
                'name': 'VirusTotal',
                'url': 'https://www.virustotal.com/api/v3/ip_addresses/{indicator}',
                'enabled': True,
                'api_key_required': True
            }
        ]

    async def check_threat_intel(self, indicator: str, indicator_type: str = 'ip') -> Dict[str, Any]:
        cache_key = f"threat_intel:{indicator_type}:{indicator}"
        
        cached_result = self.cache.get(cache_key)
        if cached_result:
            return cached_result

        try:
            results = {
                'indicator': indicator,
                'indicator_type': indicator_type,
                'sources_checked': [],
                'threat_score': 0,
                'confidence': 0,
                'malicious_count': 0,
                'suspicious_count': 0,
                'clean_count': 0,
                'last_updated': datetime.utcnow().isoformat(),
                'sources': {}
            }

            tasks = []
            for feed in self.threat_feeds:
                if feed['enabled']:
                    task = self._query_threat_feed(feed, indicator, indicator_type)
                    tasks.append(task)

            if tasks:
                feed_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(feed_results):
                    if not isinstance(result, Exception) and result:
                        feed_name = self.threat_feeds[i]['name']
                        results['sources'][feed_name] = result
                        results['sources_checked'].append(feed_name)
                        
                        if result.get('malicious', False):
                            results['malicious_count'] += 1
                        elif result.get('suspicious', False):
                            results['suspicious_count'] += 1
                        else:
                            results['clean_count'] += 1

            results['threat_score'] = self._calculate_threat_score(results)
            results['confidence'] = self._calculate_confidence(results)

            self.cache.set(cache_key, results, self.cache_ttl)
            return results

        except Exception as e:
            logger.error(f"Threat intelligence check failed for {indicator}: {e}")
            return self._get_default_threat_result(indicator, indicator_type)

    async def _query_threat_feed(self, feed: Dict[str, Any], indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        try:
            if feed['name'] == 'AbuseIPDB':
                return await self._query_abuseipdb(indicator)
            elif feed['name'] == 'VirusTotal':
                return await self._query_virustotal(indicator, indicator_type)
            elif feed['name'] == 'AlienVault OTX':
                return await self._query_alienvault(indicator, indicator_type)
            else:
                return None
                
        except Exception as e:
            logger.warning(f"Threat feed {feed['name']} query failed: {e}")
            return None

    async def _query_abuseipdb(self, ip_address: str) -> Dict[str, Any]:
        try:
            api_key = getattr(settings, 'abuseipdb_api_key', None)
            if not api_key:
                return {'error': 'API key not configured'}

            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }

            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = data.get('data', {})
                        
                        return {
                            'malicious': result.get('abuseConfidenceScore', 0) > 50,
                            'suspicious': result.get('abuseConfidenceScore', 0) > 20,
                            'confidence_score': result.get('abuseConfidenceScore', 0),
                            'total_reports': result.get('totalReports', 0),
                            'last_reported': result.get('lastReportedAt'),
                            'isp': result.get('isp'),
                            'country': result.get('countryCode')
                        }
                    else:
                        return {'error': f"HTTP {response.status}"}

        except Exception as e:
            logger.error(f"AbuseIPDB query failed: {e}")
            return {'error': str(e)}

    async def _query_virustotal(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        try:
            api_key = getattr(settings, 'virustotal_api_key', None)
            if not api_key:
                return {'error': 'API key not configured'}

            headers = {
                'x-apikey': api_key
            }

            if indicator_type == 'ip':
                url = f'https://www.virustotal.com/api/v3/ip_addresses/{indicator}'
            elif indicator_type == 'domain':
                url = f'https://www.virustotal.com/api/v3/domains/{indicator}'
            else:
                return {'error': 'Unsupported indicator type'}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = data.get('data', {}).get('attributes', {})
                        
                        stats = result.get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        total = sum(stats.values())
                        
                        return {
                            'malicious': malicious > 0,
                            'suspicious': suspicious > 0,
                            'malicious_count': malicious,
                            'suspicious_count': suspicious,
                            'total_engines': total,
                            'reputation': result.get('reputation', 0),
                            'last_analysis_date': result.get('last_analysis_date')
                        }
                    else:
                        return {'error': f"HTTP {response.status}"}

        except Exception as e:
            logger.error(f"VirusTotal query failed: {e}")
            return {'error': str(e)}

    async def _query_alienvault(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        try:
            api_key = getattr(settings, 'alienvault_api_key', None)
            if not api_key:
                return {'error': 'API key not configured'}

            headers = {
                'X-OTX-API-KEY': api_key
            }

            if indicator_type == 'ip':
                url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general'
            elif indicator_type == 'domain':
                url = f'https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general'
            else:
                return {'error': 'Unsupported indicator type'}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        pulse_count = data.get('pulse_info', {}).get('count', 0)
                        reputation = data.get('reputation', 0)
                        
                        return {
                            'malicious': pulse_count > 0,
                            'suspicious': reputation < 0,
                            'pulse_count': pulse_count,
                            'reputation': reputation,
                            'tags': [pulse.get('name') for pulse in data.get('pulse_info', {}).get('pulses', [])],
                            'related_indicators': len(data.get('pulse_info', {}).get('related', {}).get('alienvault', {}).get('pulse_info', []))
                        }
                    else:
                        return {'error': f"HTTP {response.status}"}

        except Exception as e:
            logger.error(f"AlienVault OTX query failed: {e}")
            return {'error': str(e)}

    def _calculate_threat_score(self, results: Dict[str, Any]) -> float:
        malicious_weight = 1.0
        suspicious_weight = 0.5
        
        total_sources = len(results['sources_checked'])
        if total_sources == 0:
            return 0.0
        
        score = (results['malicious_count'] * malicious_weight + 
                results['suspicious_count'] * suspicious_weight) / total_sources
        
        return min(score, 1.0)

    def _calculate_confidence(self, results: Dict[str, Any]) -> float:
        total_sources = len(results['sources_checked'])
        if total_sources == 0:
            return 0.0
        
        agreement = results['malicious_count'] + results['suspicious_count']
        confidence = agreement / total_sources
        
        return min(confidence, 1.0)

    def _get_default_threat_result(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        return {
            'indicator': indicator,
            'indicator_type': indicator_type,
            'sources_checked': [],
            'threat_score': 0.0,
            'confidence': 0.0,
            'malicious_count': 0,
            'suspicious_count': 0,
            'clean_count': 0,
            'last_updated': datetime.utcnow().isoformat(),
            'sources': {},
            'error': 'Threat intelligence check failed'
        }

    async def update_threat_feeds(self):
        logger.info("Updating threat intelligence feeds")
        
        for feed in self.threat_feeds:
            if feed['enabled']:
                try:
                    await self._update_feed_data(feed)
                except Exception as e:
                    logger.error(f"Failed to update feed {feed['name']}: {e}")

    async def _update_feed_data(self, feed: Dict[str, Any]):
        pass

    def get_service_status(self) -> Dict[str, Any]:
        enabled_feeds = [feed for feed in self.threat_feeds if feed['enabled']]
        
        return {
            'status': 'active',
            'enabled_feeds_count': len(enabled_feeds),
            'total_feeds': len(self.threat_feeds),
            'cache_ttl': self.cache_ttl,
            'feeds': [feed['name'] for feed in enabled_feeds]
        }

threat_intel_service = ThreatIntelService()

async def check_threat_intel(indicator: str, indicator_type: str = 'ip') -> Dict[str, Any]:
    return await threat_intel_service.check_threat_intel(indicator, indicator_type)

async def update_threat_feeds():
    return await threat_intel_service.update_threat_feeds()