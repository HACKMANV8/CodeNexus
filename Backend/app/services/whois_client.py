"""
WHOIS Client Service
Domain and IP registration information
"""

import logging
import whois
import aiohttp
from typing import Dict, Any, Optional
from datetime import datetime

from app.core.cache import cache_manager

logger = logging.getLogger(__name__)

class WhoisClient:
    def __init__(self):
        self.cache = cache_manager
        self.cache_ttl = 86400
        self.session = None

    async def get_whois_info(self, domain_or_ip: str) -> Dict[str, Any]:
        cache_key = f"whois:{domain_or_ip}"
        
        cached_data = self.cache.get(cache_key)
        if cached_data:
            return cached_data

        try:
            if self._is_ip_address(domain_or_ip):
                result = await self._get_ip_whois(domain_or_ip)
            else:
                result = await self._get_domain_whois(domain_or_ip)

            self.cache.set(cache_key, result, self.cache_ttl)
            return result

        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain_or_ip}: {e}")
            return self._get_default_whois_data(domain_or_ip)

    async def _get_domain_whois(self, domain: str) -> Dict[str, Any]:
        try:
            domain_info = whois.whois(domain)
            
            return {
                'query': domain,
                'type': 'domain',
                'domain_name': domain_info.domain_name,
                'registrar': domain_info.registrar,
                'whois_server': domain_info.whois_server,
                'referral_url': domain_info.referral_url,
                'updated_date': self._format_date(domain_info.updated_date),
                'creation_date': self._format_date(domain_info.creation_date),
                'expiration_date': self._format_date(domain_info.expiration_date),
                'name_servers': domain_info.name_servers,
                'status': domain_info.status,
                'emails': domain_info.emails,
                'dnssec': domain_info.dnssec,
                'name': domain_info.name,
                'org': domain_info.org,
                'address': domain_info.address,
                'city': domain_info.city,
                'state': domain_info.state,
                'zipcode': domain_info.zipcode,
                'country': domain_info.country,
                'risk_score': self._calculate_domain_risk(domain_info),
                'is_suspicious': self._is_suspicious_domain(domain_info),
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Domain WHOIS lookup failed for {domain}: {e}")
            return self._get_default_whois_data(domain)

    async def _get_ip_whois(self, ip_address: str) -> Dict[str, Any]:
        try:
            ip_info = whois.whois(ip_address)
            
            return {
                'query': ip_address,
                'type': 'ip',
                'asn': ip_info.asn,
                'asn_cidr': ip_info.asn_cidr,
                'asn_country_code': ip_info.asn_country_code,
                'asn_date': ip_info.asn_date,
                'asn_description': ip_info.asn_description,
                'asn_registry': ip_info.asn_registry,
                'nets': ip_info.nets,
                'risk_score': self._calculate_ip_risk(ip_info),
                'is_suspicious': self._is_suspicious_ip(ip_info),
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"IP WHOIS lookup failed for {ip_address}: {e}")
            return self._get_default_whois_data(ip_address)

    def _is_ip_address(self, query: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(query)
            return True
        except ValueError:
            return False

    def _format_date(self, date_value) -> Optional[str]:
        if not date_value:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0] if date_value else None
        
        if isinstance(date_value, datetime):
            return date_value.isoformat()
        elif isinstance(date_value, str):
            return date_value
        else:
            return None

    def _calculate_domain_risk(self, domain_info) -> float:
        risk_score = 0.0
        
        if domain_info.creation_date:
            creation_date = self._parse_date(domain_info.creation_date)
            if creation_date:
                domain_age = (datetime.utcnow() - creation_date).days
                if domain_age < 30:
                    risk_score += 0.3
                elif domain_age < 90:
                    risk_score += 0.1
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz']
        if any(domain_info.domain_name.lower().endswith(tld) for tld in suspicious_tlds):
            risk_score += 0.2
        
        if domain_info.registrar and any(suspect in domain_info.registrar.lower() for suspect in ['privacy', 'anonymous', 'proxy']):
            risk_score += 0.2
        
        return min(risk_score, 1.0)

    def _calculate_ip_risk(self, ip_info) -> float:
        risk_score = 0.0
        
        if ip_info.asn_description:
            desc_lower = ip_info.asn_description.lower()
            if any(keyword in desc_lower for keyword in ['hosting', 'data center', 'server']):
                risk_score += 0.2
        
        if ip_info.asn_country_code in ['CN', 'RU', 'KP', 'IR']:
            risk_score += 0.2
        
        return min(risk_score, 1.0)

    def _is_suspicious_domain(self, domain_info) -> bool:
        risk_score = self._calculate_domain_risk(domain_info)
        return risk_score > 0.5

    def _is_suspicious_ip(self, ip_info) -> bool:
        risk_score = self._calculate_ip_risk(ip_info)
        return risk_score > 0.3

    def _parse_date(self, date_value) -> Optional[datetime]:
        try:
            if isinstance(date_value, datetime):
                return date_value
            elif isinstance(date_value, str):
                return datetime.fromisoformat(date_value.replace('Z', '+00:00'))
            elif isinstance(date_value, list) and date_value:
                return self._parse_date(date_value[0])
            else:
                return None
        except:
            return None

    def _get_default_whois_data(self, query: str) -> Dict[str, Any]:
        return {
            'query': query,
            'type': 'unknown',
            'error': 'WHOIS lookup failed',
            'timestamp': datetime.utcnow().isoformat(),
            'risk_score': 0.0,
            'is_suspicious': False
        }

    async def get_domain_info(self, domain: str) -> Dict[str, Any]:
        whois_data = await self.get_whois_info(domain)
        
        return {
            'domain': domain,
            'age_days': self._calculate_domain_age(whois_data.get('creation_date')),
            'registrar': whois_data.get('registrar'),
            'expires_in_days': self._calculate_days_until_expiry(whois_data.get('expiration_date')),
            'risk_level': 'high' if whois_data.get('is_suspicious') else 'medium' if whois_data.get('risk_score', 0) > 0.3 else 'low',
            'name_servers_count': len(whois_data.get('name_servers', [])),
            'registration_details': {
                'created': whois_data.get('creation_date'),
                'updated': whois_data.get('updated_date'),
                'expires': whois_data.get('expiration_date')
            }
        }

    def _calculate_domain_age(self, creation_date: Optional[str]) -> Optional[int]:
        if not creation_date:
            return None
        
        created = self._parse_date(creation_date)
        if not created:
            return None
        
        return (datetime.utcnow() - created).days

    def _calculate_days_until_expiry(self, expiration_date: Optional[str]) -> Optional[int]:
        if not expiration_date:
            return None
        
        expires = self._parse_date(expiration_date)
        if not expires:
            return None
        
        return (expires - datetime.utcnow()).days

    def get_service_status(self) -> Dict[str, Any]:
        return {
            'status': 'active',
            'cache_enabled': True,
            'cache_ttl': self.cache_ttl,
            'supports_domains': True,
            'supports_ips': True
        }

whois_client = WhoisClient()

async def get_whois_info(domain_or_ip: str) -> Dict[str, Any]:
    return await whois_client.get_whois_info(domain_or_ip)

async def get_domain_info(domain: str) -> Dict[str, Any]:
    return await whois_client.get_domain_info(domain)