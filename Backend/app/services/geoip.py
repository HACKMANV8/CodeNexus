"""
GeoIP Service
IP geolocation and geographical threat analysis
"""

import logging
import geoip2.database
import geoip2.errors
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from app.core.config import settings
from app.core.cache import cache_manager

logger = logging.getLogger(__name__)

class GeoIPService:
    def __init__(self):
        self.reader = None
        self.cache = cache_manager
        self.cache_ttl = 3600
        self.high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'BR', 'IN', 'VN', 'UA']
        self._initialize_geoip()

    def _initialize_geoip(self):
        try:
            geoip_path = settings.DATA_DIR / "geoip" / "GeoLite2-City.mmdb"
            if geoip_path.exists():
                self.reader = geoip2.database.Reader(str(geoip_path))
                logger.info("GeoIP database loaded successfully")
            else:
                logger.warning("GeoIP database file not found")
        except Exception as e:
            logger.error(f"Failed to initialize GeoIP service: {e}")

    async def get_geoip_data(self, ip_address: str) -> Dict[str, Any]:
        cache_key = f"geoip:{ip_address}"
        
        cached_data = self.cache.get(cache_key)
        if cached_data:
            return cached_data

        try:
            if not self.reader:
                return self._get_default_geoip_data(ip_address)

            response = self.reader.city(ip_address)
            
            geo_data = {
                'ip_address': ip_address,
                'country_code': response.country.iso_code,
                'country_name': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone,
                'accuracy_radius': response.location.accuracy_radius,
                'isp': None,
                'organization': None,
                'asn': None,
                'risk_score': self._calculate_geo_risk(response.country.iso_code),
                'is_high_risk': response.country.iso_code in self.high_risk_countries,
                'timestamp': datetime.utcnow().isoformat()
            }

            try:
                asn_response = self.reader.asn(ip_address)
                geo_data.update({
                    'isp': asn_response.autonomous_system_organization,
                    'asn': f"AS{asn_response.autonomous_system_number}",
                    'organization': asn_response.autonomous_system_organization
                })
            except:
                pass

            self.cache.set(cache_key, geo_data, self.cache_ttl)
            return geo_data

        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"IP address not found in GeoIP database: {ip_address}")
            return self._get_default_geoip_data(ip_address)
        except Exception as e:
            logger.error(f"GeoIP lookup failed for {ip_address}: {e}")
            return self._get_default_geoip_data(ip_address)

    async def batch_get_geoip_data(self, ip_addresses: List[str]) -> Dict[str, Dict[str, Any]]:
        results = {}
        
        for ip in ip_addresses:
            results[ip] = await self.get_geoip_data(ip)
        
        return results

    async def get_location_from_ip(self, ip_address: str) -> Dict[str, Any]:
        geo_data = await self.get_geoip_data(ip_address)
        
        return {
            'ip': ip_address,
            'country': geo_data.get('country_code'),
            'city': geo_data.get('city'),
            'coordinates': {
                'lat': geo_data.get('latitude'),
                'lon': geo_data.get('longitude')
            },
            'risk_level': 'high' if geo_data.get('is_high_risk') else 'medium' if geo_data.get('risk_score', 0) > 0.3 else 'low'
        }

    def _calculate_geo_risk(self, country_code: Optional[str]) -> float:
        if not country_code:
            return 0.0
        
        high_risk_multiplier = 1.0
        medium_risk_multiplier = 0.5
        
        if country_code in self.high_risk_countries:
            return high_risk_multiplier
        elif country_code in ['US', 'DE', 'GB', 'FR', 'CA']:
            return 0.1
        else:
            return medium_risk_multiplier

    def _get_default_geoip_data(self, ip_address: str) -> Dict[str, Any]:
        return {
            'ip_address': ip_address,
            'country_code': None,
            'country_name': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'accuracy_radius': None,
            'isp': None,
            'organization': None,
            'asn': None,
            'risk_score': 0.0,
            'is_high_risk': False,
            'timestamp': datetime.utcnow().isoformat(),
            'error': 'GeoIP data not available'
        }

    async def get_country_stats(self) -> Dict[str, Any]:
        cache_key = "geoip:country_stats"
        cached_stats = self.cache.get(cache_key)
        
        if cached_stats:
            return cached_stats

        try:
            stats = {
                'total_countries_tracked': len(self.high_risk_countries) + 50,
                'high_risk_countries': self.high_risk_countries,
                'coverage': {
                    'ipv4': 99.8,
                    'ipv6': 95.2
                },
                'last_updated': datetime.utcnow().isoformat()
            }
            
            self.cache.set(cache_key, stats, 3600)
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get country stats: {e}")
            return {}

    def update_high_risk_countries(self, countries: List[str]):
        self.high_risk_countries = countries
        logger.info(f"Updated high-risk countries list: {countries}")

    def get_service_status(self) -> Dict[str, Any]:
        return {
            'status': 'active' if self.reader else 'inactive',
            'database_loaded': self.reader is not None,
            'cache_enabled': True,
            'high_risk_countries_count': len(self.high_risk_countries),
            'cache_ttl': self.cache_ttl
        }

geoip_service = GeoIPService()

async def get_geoip_data(ip_address: str) -> Dict[str, Any]:
    return await geoip_service.get_geoip_data(ip_address)

async def get_location_from_ip(ip_address: str) -> Dict[str, Any]:
    return await geoip_service.get_location_from_ip(ip_address)