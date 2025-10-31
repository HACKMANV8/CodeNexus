"""
Event Enrichment Pipeline
Enhances raw attack events with threat intelligence and contextual data
"""

import logging
from typing import Dict, Any, Optional
import geoip2.database
import requests
from datetime import datetime

from app.models.database_models import AttackEvent, AttackerProfile
from app.core.database import get_db
from app.core.config import settings

logger = logging.getLogger(__name__)

class EnrichmentEngine:
    def __init__(self):
        self.geoip_reader = self._setup_geoip()
        self.threat_intel_sources = [
            "alienvault",
            "virustotal", 
            "abuseipdb"
        ]

    def _setup_geoip(self):
        try:
            geoip_path = settings.DATA_DIR / "geoip" / "GeoLite2-City.mmdb"
            return geoip2.database.Reader(str(geoip_path))
        except Exception as e:
            logger.warning(f"GeoIP database not available: {e}")
            return None

    async def enrich_event(self, attack_event: AttackEvent) -> AttackEvent:
        enriched_data = {}
        
        enriched_data.update(await self._enrich_geolocation(attack_event.source_ip))
        enriched_data.update(await self._enrich_threat_intel(attack_event.source_ip))
        enriched_data.update(await self._enrich_network_info(attack_event.source_ip))
        
        for key, value in enriched_data.items():
            if hasattr(attack_event, key):
                setattr(attack_event, key, value)
        
        return attack_event

    async def _enrich_geolocation(self, ip_address: str) -> Dict[str, Any]:
        geo_data = {}
        
        try:
            if self.geoip_reader:
                response = self.geoip_reader.city(ip_address)
                geo_data = {
                    "country": response.country.iso_code,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude
                }
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
        
        return geo_data

    async def _enrich_threat_intel(self, ip_address: str) -> Dict[str, Any]:
        threat_data = {
            "threat_level": "low",
            "tags": []
        }
        
        try:
            abuseipdb_score = await self._check_abuseipdb(ip_address)
            if abuseipdb_score > 50:
                threat_data["threat_level"] = "high"
                threat_data["tags"].append("malicious_ip")
            
            virustotal_data = await self._check_virustotal(ip_address)
            if virustotal_data.get("malicious", 0) > 0:
                threat_data["threat_level"] = "medium"
                threat_data["tags"].append("suspicious_ip")
                
        except Exception as e:
            logger.debug(f"Threat intelligence lookup failed: {e}")
        
        return threat_data

    async def _enrich_network_info(self, ip_address: str) -> Dict[str, Any]:
        network_data = {}
        
        try:
            if self.geoip_reader:
                response = self.geoip_reader.asn(ip_address)
                network_data = {
                    "asn": f"AS{response.autonomous_system_number}",
                    "organization": response.autonomous_system_organization
                }
        except Exception as e:
            logger.debug(f"ASN lookup failed for {ip_address}: {e}")
        
        return network_data

    async def _check_abuseipdb(self, ip_address: str) -> int:
        return 0

    async def _check_virustotal(self, ip_address: str) -> Dict[str, Any]:
        return {"malicious": 0}

    async def update_attacker_profile(self, attack_event: AttackEvent):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            profile = db.query(AttackerProfile).filter(
                AttackerProfile.ip_address == attack_event.source_ip
            ).first()
            
            if not profile:
                profile = AttackerProfile(
                    ip_address=attack_event.source_ip,
                    first_seen=attack_event.timestamp,
                    last_seen=attack_event.timestamp,
                    attack_count=1,
                    country=attack_event.country,
                    asn=attack_event.asn,
                    organization=attack_event.organization
                )
                db.add(profile)
            else:
                profile.last_seen = attack_event.timestamp
                profile.attack_count += 1
                if attack_event.country:
                    profile.country = attack_event.country
            
            db.commit()
            logger.debug(f"Updated attacker profile for {attack_event.source_ip}")
            
        except Exception as e:
            logger.error(f"Failed to update attacker profile: {e}")
        finally:
            db.close()

async def enrich_attack_event(attack_event: AttackEvent) -> AttackEvent:
    engine = EnrichmentEngine()
    enriched_event = await engine.enrich_event(attack_event)
    await engine.update_attacker_profile(enriched_event)
    return enriched_event