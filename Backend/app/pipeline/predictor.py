"""
Behavior Prediction Pipeline
Predicts attacker behavior and future actions
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import numpy as np

from app.models.database_models import AttackerProfile, AttackEvent
from app.models.attack_models import BehavioralSignature, AttackTimeline
from app.core.database import get_db

logger = logging.getLogger(__name__)

class PredictionEngine:
    def __init__(self):
        self.behavior_patterns = self._load_behavior_patterns()
        self.prediction_horizon = 24

    def _load_behavior_patterns(self) -> List[BehavioralSignature]:
        return [
            BehavioralSignature(
                signature_id="brute_force_pattern",
                name="SSH Brute Force Pattern",
                description="Rapid sequential login attempts",
                patterns=["multiple_failed_logins", "common_usernames", "password_spray"],
                confidence=0.85,
                false_positive_rate=0.1,
                detection_logic={"window_minutes": 5, "attempt_threshold": 10},
                required_events=3
            ),
            BehavioralSignature(
                signature_id="web_scan_pattern", 
                name="Web Vulnerability Scan",
                description="Systematic URL probing for vulnerabilities",
                patterns=["directory_enumeration", "parameter_fuzzing", "header_injection"],
                confidence=0.78,
                false_positive_rate=0.15,
                detection_logic={"request_rate": "high", "status_codes": "mixed"},
                required_events=5
            )
        ]

    async def predict_attacker_behavior(self, attacker_ip: str) -> Dict[str, Any]:
        prediction = {
            "attacker_ip": attacker_ip,
            "next_likely_actions": [],
            "risk_score": 0.0,
            "confidence": 0.0,
            "timeline": None,
            "recommendations": []
        }

        try:
            attacker_profile = await self._get_attacker_profile(attacker_ip)
            recent_events = await self._get_recent_events(attacker_ip)
            
            if not recent_events:
                return prediction

            behavior_pattern = await self._analyze_behavior_pattern(recent_events)
            next_actions = await self._predict_next_actions(behavior_pattern, recent_events)
            risk_score = await self._calculate_risk_score(attacker_profile, behavior_pattern)
            timeline = await self._generate_timeline(attacker_ip, recent_events, next_actions)

            prediction.update({
                "next_likely_actions": next_actions,
                "risk_score": risk_score,
                "confidence": behavior_pattern.get("confidence", 0.0),
                "timeline": timeline,
                "recommendations": self._generate_recommendations(behavior_pattern, risk_score)
            })

        except Exception as e:
            logger.error(f"Behavior prediction failed for {attacker_ip}: {e}")

        return prediction

    async def _get_attacker_profile(self, attacker_ip: str) -> Optional[AttackerProfile]:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            profile = db.query(AttackerProfile).filter(
                AttackerProfile.ip_address == attacker_ip
            ).first()
            
            return profile
            
        except Exception as e:
            logger.debug(f"Failed to get attacker profile: {e}")
            return None
        finally:
            db.close()

    async def _get_recent_events(self, attacker_ip: str, hours: int = 24) -> List[AttackEvent]:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            from datetime import datetime, timedelta
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            
            events = db.query(AttackEvent).filter(
                AttackEvent.source_ip == attacker_ip,
                AttackEvent.timestamp >= time_threshold
            ).order_by(AttackEvent.timestamp.asc()).all()
            
            return events
            
        except Exception as e:
            logger.debug(f"Failed to get recent events: {e}")
            return []
        finally:
            db.close()

    async def _analyze_behavior_pattern(self, events: List[AttackEvent]) -> Dict[str, Any]:
        if not events:
            return {"pattern": "unknown", "confidence": 0.0}

        event_types = [event.honeypot_type for event in events]
        last_event = events[-1]

        pattern_analysis = {
            "primary_technique": self._identify_primary_technique(events),
            "attack_phase": self._determine_attack_phase(events),
            "sophistication": self._assess_sophistication(events),
            "persistence": self._measure_persistence(events),
            "confidence": 0.7
        }

        for behavior_pattern in self.behavior_patterns:
            if self._matches_pattern(events, behavior_pattern):
                pattern_analysis["matched_pattern"] = behavior_pattern.name
                pattern_analysis["confidence"] = behavior_pattern.confidence
                break

        return pattern_analysis

    async def _predict_next_actions(self, behavior_pattern: Dict[str, Any], events: List[AttackEvent]) -> List[Dict[str, Any]]:
        next_actions = []

        primary_technique = behavior_pattern.get("primary_technique")
        attack_phase = behavior_pattern.get("attack_phase")

        action_predictions = {
            "reconnaissance": [
                {"action": "port_scan", "probability": 0.8, "timeframe": "1h"},
                {"action": "service_detection", "probability": 0.6, "timeframe": "2h"}
            ],
            "exploitation": [
                {"action": "privilege_escalation", "probability": 0.7, "timeframe": "30m"},
                {"action": "lateral_movement", "probability": 0.5, "timeframe": "1h"}
            ],
            "persistence": [
                {"action": "backdoor_installation", "probability": 0.6, "timeframe": "15m"},
                {"action": "data_exfiltration", "probability": 0.4, "timeframe": "2h"}
            ]
        }

        return action_predictions.get(attack_phase, [])

    async def _calculate_risk_score(self, profile: Optional[AttackerProfile], behavior_pattern: Dict[str, Any]) -> float:
        base_score = 0.0

        if profile:
            base_score += min(profile.attack_count / 100.0, 1.0) * 0.3
            base_score += profile.threat_score / 100.0 * 0.3

        base_score += behavior_pattern.get("confidence", 0.0) * 0.4

        sophistication_boost = behavior_pattern.get("sophistication", 0.0) * 0.2
        persistence_boost = behavior_pattern.get("persistence", 0.0) * 0.2

        return min(base_score + sophistication_boost + persistence_boost, 1.0)

    async def _generate_timeline(self, attacker_ip: str, events: List[AttackEvent], predictions: List[Dict[str, Any]]) -> AttackTimeline:
        event_dicts = []
        for event in events:
            event_dicts.append({
                "timestamp": event.timestamp,
                "type": event.honeypot_type,
                "action": self._map_event_to_action(event),
                "confidence": event.ml_confidence or 0.0
            })

        return AttackTimeline(
            timeline_id=f"timeline_{attacker_ip}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            attacker_ip=attacker_ip,
            start_time=events[0].timestamp if events else datetime.utcnow(),
            end_time=datetime.utcnow() + timedelta(hours=self.prediction_horizon),
            events=event_dicts,
            attack_sequence=[event.honeypot_type for event in events],
            techniques_used=list(set([self._map_event_to_technique(event) for event in events])),
            risk_score=await self._calculate_risk_score(None, {}),
            duration_seconds=0.0
        )

    def _generate_recommendations(self, behavior_pattern: Dict[str, Any], risk_score: float) -> List[str]:
        recommendations = []

        if risk_score > 0.8:
            recommendations.append("Immediate IP blocking recommended")
            recommendations.append("Enable enhanced logging for this attacker")
        elif risk_score > 0.6:
            recommendations.append("Monitor for further activity")
            recommendations.append("Consider temporary IP restriction")

        if behavior_pattern.get("matched_pattern") == "SSH Brute Force Pattern":
            recommendations.append("Implement fail2ban or similar protection")
            recommendations.append("Review SSH configuration for weak settings")

        return recommendations

    def _identify_primary_technique(self, events: List[AttackEvent]) -> str:
        techniques = [event.honeypot_type for event in events]
        return max(set(techniques), key=techniques.count) if techniques else "unknown"

    def _determine_attack_phase(self, events: List[AttackEvent]) -> str:
        event_count = len(events)
        if event_count < 3:
            return "reconnaissance"
        elif event_count < 10:
            return "exploitation"
        else:
            return "persistence"

    def _assess_sophistication(self, events: List[AttackEvent]) -> float:
        sophistication_indicators = 0
        total_events = len(events)

        for event in events:
            if event.payload and len(event.payload) > 1000:
                sophistication_indicators += 1
            if event.user_agent and any(tool in event.user_agent.lower() for tool in ["nmap", "sqlmap", "metasploit"]):
                sophistication_indicators += 1

        return sophistication_indicators / total_events if total_events > 0 else 0.0

    def _measure_persistence(self, events: List[AttackEvent]) -> float:
        if len(events) < 2:
            return 0.0

        timestamps = [event.timestamp.timestamp() for event in events]
        time_range = max(timestamps) - min(timestamps)
        
        return min(len(events) / (time_range / 3600 + 1), 1.0)

    def _matches_pattern(self, events: List[AttackEvent], pattern: BehavioralSignature) -> bool:
        return len(events) >= pattern.required_events

    def _map_event_to_action(self, event: AttackEvent) -> str:
        mapping = {
            "ssh": "authentication_attempt",
            "web": "http_request", 
            "ftp": "file_transfer_attempt"
        }
        return mapping.get(event.honeypot_type, "unknown_action")

    def _map_event_to_technique(self, event: AttackEvent) -> str:
        mapping = {
            "ssh": "T1110",  # Brute Force
            "web": "T1595",  # Active Scanning
            "ftp": "T1105"   # Ingress Tool Transfer
        }
        return mapping.get(event.honeypot_type, "T1046")  # Network Service Scanning

async def predict_attacker_behavior(attacker_ip: str) -> Dict[str, Any]:
    engine = PredictionEngine()
    return await engine.predict_attacker_behavior(attacker_ip)