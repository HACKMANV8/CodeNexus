"""
Response Action Pipeline
Generates and executes automated response actions
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from app.models.database_models import ResponseAction, AttackEvent
from app.models.schemas import ResponseActionCreate, ResponseActionType
from app.core.database import get_db
from app.core.config import settings

logger = logging.getLogger(__name__)

class ResponseEngine:
    def __init__(self):
        self.response_rules = self._load_response_rules()
        self.auto_approve_threshold = 0.9
        self.max_auto_responses = 10

    def _load_response_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "high_confidence_malicious",
                "conditions": {
                    "threat_level": ["high", "critical"],
                    "confidence": 0.85,
                    "attack_count": 5
                },
                "actions": [
                    {"type": ResponseActionType.BLOCK_IP, "priority": "high", "ttl": 86400}
                ]
            },
            {
                "name": "suspicious_behavior", 
                "conditions": {
                    "threat_level": ["medium"],
                    "confidence": 0.7,
                    "attack_pattern": "brute_force"
                },
                "actions": [
                    {"type": ResponseActionType.ALERT, "priority": "medium", "ttl": 3600}
                ]
            },
            {
                "name": "reconnaissance_activity",
                "conditions": {
                    "threat_level": ["low", "medium"],
                    "attack_pattern": "scanning"
                },
                "actions": [
                    {"type": ResponseActionType.LOG, "priority": "low", "ttl": 1800}
                ]
            }
        ]

    async def generate_response_action(self, attack_event: AttackEvent, classification: Dict[str, Any]) -> Optional[ResponseActionCreate]:
        response_actions = []

        try:
            for rule in self.response_rules:
                if await self._evaluate_rule(rule, attack_event, classification):
                    for action_config in rule["actions"]:
                        response_action = await self._create_response_action(
                            attack_event, classification, action_config
                        )
                        response_actions.append(response_action)

            if response_actions:
                primary_action = self._select_primary_action(response_actions)
                return primary_action

        except Exception as e:
            logger.error(f"Response generation failed: {e}")

        return None

    async def _evaluate_rule(self, rule: Dict[str, Any], attack_event: AttackEvent, classification: Dict[str, Any]) -> bool:
        conditions = rule["conditions"]
        
        if "threat_level" in conditions:
            if classification.get("threat_level") not in conditions["threat_level"]:
                return False

        if "confidence" in conditions:
            if classification.get("confidence", 0) < conditions["confidence"]:
                return False

        if "attack_count" in conditions:
            attack_count = await self._get_attack_count(attack_event.source_ip)
            if attack_count < conditions["attack_count"]:
                return False

        if "attack_pattern" in conditions:
            if not await self._check_attack_pattern(attack_event, conditions["attack_pattern"]):
                return False

        return True

    async def _create_response_action(self, attack_event: AttackEvent, classification: Dict[str, Any], action_config: Dict[str, Any]) -> ResponseActionCreate:
        action_details = {
            "reason": f"Automated response based on {classification.get('threat_level', 'unknown')} threat",
            "confidence": classification.get("confidence", 0),
            "triggering_event": attack_event.event_id,
            "rule_applied": action_config.get("name", "unknown")
        }

        return ResponseActionCreate(
            event_id=attack_event.event_id,
            attacker_ip=attack_event.source_ip,
            action_type=action_config["type"],
            action_details=action_details,
            ttl=action_config.get("ttl", 3600)
        )

    def _select_primary_action(self, actions: List[ResponseActionCreate]) -> ResponseActionCreate:
        action_priority = {
            ResponseActionType.BLOCK_IP: 4,
            ResponseActionType.QUARANTINE: 3,
            ResponseActionType.ALERT: 2,
            ResponseActionType.LOG: 1,
            ResponseActionType.ALLOW_IP: 0
        }

        return max(actions, key=lambda x: action_priority.get(x.action_type, 0))

    async def execute_response_action(self, response_action: ResponseActionCreate, approved_by: Optional[str] = None) -> bool:
        try:
            requires_approval = await self._requires_approval(response_action)
            
            if requires_approval and not approved_by:
                logger.info(f"Response action requires approval: {response_action.action_type}")
                return await self._queue_for_approval(response_action)

            execution_result = await self._execute_action(response_action, approved_by)
            
            if execution_result:
                await self._store_response_action(response_action, "executed", approved_by)
                logger.info(f"Response action executed: {response_action.action_type} for {response_action.attacker_ip}")
            else:
                await self._store_response_action(response_action, "failed", approved_by)
                logger.error(f"Response action failed: {response_action.action_type}")

            return execution_result

        except Exception as e:
            logger.error(f"Response execution failed: {e}")
            return False

    async def _requires_approval(self, response_action: ResponseActionCreate) -> bool:
        high_risk_actions = [ResponseActionType.BLOCK_IP, ResponseActionType.QUARANTINE]
        
        if response_action.action_type in high_risk_actions:
            return True

        recent_auto_responses = await self._get_recent_auto_responses()
        if recent_auto_responses >= self.max_auto_responses:
            return True

        return False

    async def _execute_action(self, response_action: ResponseActionCreate, approved_by: Optional[str]) -> bool:
        try:
            if response_action.action_type == ResponseActionType.BLOCK_IP:
                return await self._block_ip_address(response_action.attacker_ip, response_action.action_details)
            
            elif response_action.action_type == ResponseActionType.ALERT:
                return await self._send_alert(response_action)
            
            elif response_action.action_type == ResponseActionType.LOG:
                return await self._log_action(response_action)
            
            else:
                logger.warning(f"Unsupported action type: {response_action.action_type}")
                return False

        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return False

    async def _block_ip_address(self, ip_address: str, action_details: Dict[str, Any]) -> bool:
        logger.info(f"Blocking IP address: {ip_address} - Reason: {action_details.get('reason')}")
        return True

    async def _send_alert(self, response_action: ResponseActionCreate) -> bool:
        alert_message = {
            "type": "security_alert",
            "attacker_ip": response_action.attacker_ip,
            "action": response_action.action_type,
            "reason": response_action.action_details.get("reason"),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Security alert: {alert_message}")
        return True

    async def _log_action(self, response_action: ResponseActionCreate) -> bool:
        logger.info(f"Logged response action for {response_action.attacker_ip}: {response_action.action_details.get('reason')}")
        return True

    async def _queue_for_approval(self, response_action: ResponseActionCreate) -> bool:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            action = ResponseAction(
                action_id=f"pending_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                event_id=response_action.event_id,
                attacker_ip=response_action.attacker_ip,
                action_type=response_action.action_type.value,
                action_details=response_action.action_details,
                status="pending_approval",
                created_at=datetime.utcnow(),
                ttl=response_action.ttl
            )
            
            db.add(action)
            db.commit()
            
            logger.info(f"Response action queued for approval: {response_action.action_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to queue action for approval: {e}")
            return False
        finally:
            db.close()

    async def _store_response_action(self, response_action: ResponseActionCreate, status: str, approved_by: Optional[str]) -> bool:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            action = ResponseAction(
                action_id=f"action_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                event_id=response_action.event_id,
                attacker_ip=response_action.attacker_ip,
                action_type=response_action.action_type.value,
                action_details=response_action.action_details,
                status=status,
                created_by=approved_by or "system",
                created_at=datetime.utcnow(),
                executed_at=datetime.utcnow() if status == "executed" else None,
                ttl=response_action.ttl
            )
            
            db.add(action)
            db.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to store response action: {e}")
            return False
        finally:
            db.close()

    async def _get_attack_count(self, ip_address: str) -> int:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            from datetime import datetime, timedelta
            hour_ago = datetime.utcnow() - timedelta(hours=1)
            
            count = db.query(AttackEvent).filter(
                AttackEvent.source_ip == ip_address,
                AttackEvent.timestamp >= hour_ago
            ).count()
            
            return count
            
        except Exception as e:
            logger.debug(f"Failed to get attack count: {e}")
            return 0
        finally:
            db.close()

    async def _check_attack_pattern(self, attack_event: AttackEvent, pattern: str) -> bool:
        return True

    async def _get_recent_auto_responses(self) -> int:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            from datetime import datetime, timedelta
            hour_ago = datetime.utcnow() - timedelta(hours=1)
            
            count = db.query(ResponseAction).filter(
                ResponseAction.created_by == "system",
                ResponseAction.created_at >= hour_ago
            ).count()
            
            return count
            
        except Exception as e:
            logger.debug(f"Failed to get recent auto responses: {e}")
            return 0
        finally:
            db.close()

async def generate_response_action(attack_event: AttackEvent, classification: Dict[str, Any]) -> Optional[ResponseActionCreate]:
    engine = ResponseEngine()
    return await engine.generate_response_action(attack_event, classification)