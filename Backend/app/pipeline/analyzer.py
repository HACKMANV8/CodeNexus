"""
Attack Analysis Pipeline
Performs deep analysis of attack patterns and trends
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import statistics

from app.models.database_models import AttackEvent, AttackerProfile
from app.models.attack_models import AttackPattern, TTPMapping, IOC
from app.core.database import get_db

logger = logging.getLogger(__name__)

class AnalysisEngine:
    def __init__(self):
        self.ttp_mappings = self._load_ttp_mappings()
        self.analysis_window_hours = 24

    def _load_ttp_mappings(self) -> List[TTPMapping]:
        return [
            TTPMapping(
                mitre_technique_id="T1595",
                technique_name="Active Scanning",
                tactic="reconnaissance",
                description="Scanning IP blocks to gather information",
                detection_rules=["port_scan", "service_scan"],
                honeypot_indicators=["multiple_ports", "rapid_connections"],
                severity="low"
            ),
            TTPMapping(
                mitre_technique_id="T1110",
                technique_name="Brute Force",
                tactic="credential_access", 
                description="Attempting multiple authentication attempts",
                detection_rules=["failed_logins", "common_credentials"],
                honeypot_indicators=["repeated_auth_attempts", "username_enumeration"],
                severity="medium"
            ),
            TTPMapping(
                mitre_technique_id="T1190",
                technique_name="Public-Facing Application",
                tactic="initial_access",
                description="Exploiting public-facing applications",
                detection_rules=["exploit_attempts", "vulnerability_scanning"],
                honeypot_indicators=["sql_injection", "xss_attempts"],
                severity="high"
            )
        ]

    async def analyze_attack_patterns(self, time_window_hours: int = 24) -> Dict[str, Any]:
        analysis_result = {
            "timeframe": f"last_{time_window_hours}_hours",
            "total_attacks": 0,
            "unique_attackers": 0,
            "attack_distribution": {},
            "ttp_breakdown": [],
            "geographical_analysis": {},
            "trend_analysis": {},
            "top_attackers": [],
            "emerging_threats": [],
            "risk_assessment": {}
        }

        try:
            recent_events = await self._get_recent_events(time_window_hours)
            
            if not recent_events:
                return analysis_result

            analysis_result["total_attacks"] = len(recent_events)
            analysis_result["unique_attackers"] = await self._count_unique_attackers(recent_events)
            analysis_result["attack_distribution"] = await self._analyze_attack_distribution(recent_events)
            analysis_result["ttp_breakdown"] = await self._analyze_ttp_patterns(recent_events)
            analysis_result["geographical_analysis"] = await self._analyze_geographical_data(recent_events)
            analysis_result["trend_analysis"] = await self._analyze_trends(recent_events, time_window_hours)
            analysis_result["top_attackers"] = await self._identify_top_attackers(recent_events)
            analysis_result["emerging_threats"] = await self._detect_emerging_threats(recent_events)
            analysis_result["risk_assessment"] = await self._assess_overall_risk(recent_events)

        except Exception as e:
            logger.error(f"Attack pattern analysis failed: {e}")

        return analysis_result

    async def _get_recent_events(self, hours: int) -> List[AttackEvent]:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            
            events = db.query(AttackEvent).filter(
                AttackEvent.timestamp >= time_threshold
            ).order_by(AttackEvent.timestamp.desc()).all()
            
            return events
            
        except Exception as e:
            logger.error(f"Failed to get recent events: {e}")
            return []
        finally:
            db.close()

    async def _count_unique_attackers(self, events: List[AttackEvent]) -> int:
        unique_ips = set(event.source_ip for event in events)
        return len(unique_ips)

    async def _analyze_attack_distribution(self, events: List[AttackEvent]) -> Dict[str, Any]:
        distribution = {
            "by_honeypot_type": defaultdict(int),
            "by_threat_level": defaultdict(int),
            "by_hour": defaultdict(int),
            "by_country": defaultdict(int)
        }

        for event in events:
            distribution["by_honeypot_type"][event.honeypot_type] += 1
            distribution["by_threat_level"][event.threat_level] += 1
            
            hour_key = event.timestamp.strftime("%H:00")
            distribution["by_hour"][hour_key] += 1
            
            if event.country:
                distribution["by_country"][event.country] += 1

        return {
            "honeypot_types": dict(distribution["by_honeypot_type"]),
            "threat_levels": dict(distribution["by_threat_level"]),
            "hourly_pattern": dict(distribution["by_hour"]),
            "countries": dict(distribution["by_country"])
        }

    async def _analyze_ttp_patterns(self, events: List[AttackEvent]) -> List[Dict[str, Any]]:
        ttp_analysis = []

        for ttp in self.ttp_mappings:
            matching_events = []
            
            for event in events:
                if self._event_matches_ttp(event, ttp):
                    matching_events.append(event)

            if matching_events:
                ttp_analysis.append({
                    "technique_id": ttp.mitre_technique_id,
                    "technique_name": ttp.technique_name,
                    "tactic": ttp.tactic,
                    "event_count": len(matching_events),
                    "severity": ttp.severity,
                    "unique_attackers": len(set(e.source_ip for e in matching_events)),
                    "example_events": [e.event_id for e in matching_events[:3]]
                })

        return sorted(ttp_analysis, key=lambda x: x["event_count"], reverse=True)

    async def _analyze_geographical_data(self, events: List[AttackEvent]) -> Dict[str, Any]:
        geo_analysis = {
            "top_countries": [],
            "attack_density": {},
            "high_risk_regions": []
        }

        country_counts = Counter(event.country for event in events if event.country)
        geo_analysis["top_countries"] = country_counts.most_common(10)

        high_risk_countries = ["CN", "RU", "US", "BR", "IN"]
        geo_analysis["high_risk_regions"] = [
            country for country in high_risk_countries 
            if country in country_counts
        ]

        return geo_analysis

    async def _analyze_trends(self, events: List[AttackEvent], window_hours: int) -> Dict[str, Any]:
        trend_analysis = {
            "attack_volume_trend": "stable",
            "threat_level_trend": "stable",
            "emerging_patterns": [],
            "seasonal_patterns": {}
        }

        if len(events) < 2:
            return trend_analysis

        hourly_counts = defaultdict(int)
        for event in events:
            hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
            hourly_counts[hour_key] += 1

        counts = list(hourly_counts.values())
        if len(counts) >= 2:
            trend_analysis["attack_volume_trend"] = self._calculate_trend(counts)

        threat_scores = [self._threat_level_to_score(event.threat_level) for event in events]
        if threat_scores:
            avg_threat = statistics.mean(threat_scores)
            trend_analysis["threat_level_trend"] = "increasing" if avg_threat > 0.5 else "decreasing"

        return trend_analysis

    async def _identify_top_attackers(self, events: List[AttackEvent]) -> List[Dict[str, Any]]:
        attacker_stats = defaultdict(lambda: {"count": 0, "last_seen": None, "threat_levels": []})

        for event in events:
            attacker = attacker_stats[event.source_ip]
            attacker["count"] += 1
            attacker["last_seen"] = max(attacker["last_seen"] or event.timestamp, event.timestamp)
            attacker["threat_levels"].append(event.threat_level)

        top_attackers = []
        for ip, stats in attacker_stats.items():
            top_attackers.append({
                "ip_address": ip,
                "attack_count": stats["count"],
                "last_seen": stats["last_seen"],
                "avg_threat_level": statistics.mean(
                    [self._threat_level_to_score(level) for level in stats["threat_levels"]]
                ) if stats["threat_levels"] else 0,
                "preferred_techniques": self._get_attacker_techniques(ip, events)
            })

        return sorted(top_attackers, key=lambda x: x["attack_count"], reverse=True)[:10]

    async def _detect_emerging_threats(self, events: List[AttackEvent]) -> List[Dict[str, Any]]:
        emerging_threats = []

        recent_events = [e for e in events if e.timestamp > datetime.utcnow() - timedelta(hours=1)]
        if len(recent_events) < 5:
            return emerging_threats

        new_ips = set(e.source_ip for e in recent_events)
        historical_ips = await self._get_historical_ips(hours=24)

        truly_new_ips = new_ips - historical_ips
        if truly_new_ips:
            emerging_threats.append({
                "type": "new_attackers",
                "description": f"{len(truly_new_ips)} new attackers detected",
                "confidence": 0.7,
                "recommendation": "Monitor for persistent activity"
            })

        return emerging_threats

    async def _assess_overall_risk(self, events: List[AttackEvent]) -> Dict[str, Any]:
        risk_factors = {
            "attack_volume": len(events) / 100.0,
            "threat_severity": statistics.mean([self._threat_level_to_score(e.threat_level) for e in events]) if events else 0,
            "attacker_diversity": await self._count_unique_attackers(events) / 50.0,
            "ttp_sophistication": await self._assess_ttp_sophistication(events)
        }

        overall_risk = min(sum(risk_factors.values()) / len(risk_factors), 1.0)

        return {
            "overall_risk_score": overall_risk,
            "risk_level": "critical" if overall_risk > 0.8 else "high" if overall_risk > 0.6 else "medium" if overall_risk > 0.4 else "low",
            "risk_factors": risk_factors,
            "recommendations": self._generate_risk_recommendations(overall_risk)
        }

    def _event_matches_ttp(self, event: AttackEvent, ttp: TTPMapping) -> bool:
        indicators = ttp.honeypot_indicators
        
        if "multiple_ports" in indicators and event.destination_port and event.destination_port > 1000:
            return True
            
        if "repeated_auth_attempts" in indicators and event.honeypot_type == "ssh":
            return True
            
        return False

    def _calculate_trend(self, values: List[float]) -> str:
        if len(values) < 2:
            return "stable"
            
        first_half = values[:len(values)//2]
        second_half = values[len(values)//2:]
        
        avg_first = statistics.mean(first_half) if first_half else 0
        avg_second = statistics.mean(second_half) if second_half else 0
        
        if avg_second > avg_first * 1.2:
            return "increasing"
        elif avg_second < avg_first * 0.8:
            return "decreasing"
        else:
            return "stable"

    def _threat_level_to_score(self, threat_level: str) -> float:
        scores = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
        return scores.get(threat_level, 0.0)

    def _get_attacker_techniques(self, ip_address: str, events: List[AttackEvent]) -> List[str]:
        attacker_events = [e for e in events if e.source_ip == ip_address]
        techniques = list(set(e.honeypot_type for e in attacker_events))
        return techniques[:3]

    async def _get_historical_ips(self, hours: int) -> set:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            time_threshold = datetime.utcnow() - timedelta(hours=hours * 2)
            
            historical_events = db.query(AttackEvent).filter(
                AttackEvent.timestamp >= time_threshold,
                AttackEvent.timestamp < datetime.utcnow() - timedelta(hours=hours)
            ).all()
            
            return set(event.source_ip for event in historical_events)
            
        except Exception as e:
            logger.debug(f"Failed to get historical IPs: {e}")
            return set()
        finally:
            db.close()

    async def _assess_ttp_sophistication(self, events: List[AttackEvent]) -> float:
        if not events:
            return 0.0
            
        sophisticated_techniques = {"T1190", "T1068", "T1055"}
        event_techniques = set()
        
        for event in events:
            for ttp in self.ttp_mappings:
                if self._event_matches_ttp(event, ttp):
                    event_techniques.add(ttp.mitre_technique_id)
        
        sophisticated_count = len(event_techniques.intersection(sophisticated_techniques))
        return sophisticated_count / len(sophisticated_techniques) if sophisticated_techniques else 0.0

    def _generate_risk_recommendations(self, risk_score: float) -> List[str]:
        recommendations = []
        
        if risk_score > 0.8:
            recommendations.extend([
                "Activate incident response team",
                "Increase monitoring frequency", 
                "Consider external threat intelligence integration"
            ])
        elif risk_score > 0.6:
            recommendations.extend([
                "Review and update firewall rules",
                "Enhance log retention policies",
                "Conduct security awareness briefing"
            ])
        elif risk_score > 0.4:
            recommendations.extend([
                "Monitor for pattern changes",
                "Update threat detection rules",
                "Review recent attack patterns"
            ])
            
        return recommendations

async def analyze_attack_patterns(time_window_hours: int = 24) -> Dict[str, Any]:
    engine = AnalysisEngine()
    return await engine.analyze_attack_patterns(time_window_hours)