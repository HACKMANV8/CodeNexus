"""
Response Background Worker
Executes automated response actions and countermeasures
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import subprocess

from app.core.database import get_db
from app.models.database_models import ResponseAction, AttackEvent
from app.core.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

class ResponseWorker:
    def __init__(self):
        self.is_running = False
        self.processing_interval = 30
        self.max_concurrent_actions = 5
        self.active_actions = set()
        self.response_handlers = self._initialize_response_handlers()

    def _initialize_response_handlers(self) -> Dict[str, Any]:
        return {
            'block_ip': self._handle_ip_block,
            'allow_ip': self._handle_ip_allow,
            'quarantine': self._handle_quarantine,
            'alert': self._handle_alert,
            'log': self._handle_log
        }

    async def start(self):
        if self.is_running:
            logger.warning("Response worker already running")
            return

        self.is_running = True
        logger.info("Starting response background worker")

        try:
            while self.is_running:
                start_time = datetime.utcnow()
                
                try:
                    await self._process_pending_responses()
                    await self._cleanup_expired_responses()
                except Exception as e:
                    logger.error(f"Response worker processing error: {e}")

                processing_time = (datetime.utcnow() - start_time).total_seconds()
                sleep_time = max(1, self.processing_interval - processing_time)
                
                await asyncio.sleep(sleep_time)

        except asyncio.CancelledError:
            logger.info("Response worker stopped")
        except Exception as e:
            logger.error(f"Response worker crashed: {e}")
        finally:
            self.is_running = False

    async def stop(self):
        self.is_running = False
        logger.info("Stopping response worker")

    async def _process_pending_responses(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            pending_actions = db.query(ResponseAction).filter(
                ResponseAction.status == 'pending_approval',
                ResponseAction.created_at >= datetime.utcnow() - timedelta(hours=24)
            ).limit(self.max_concurrent_actions).all()

            for action in pending_actions:
                if action.action_id in self.active_actions:
                    continue

                self.active_actions.add(action.action_id)
                
                try:
                    await self._execute_response_action(action)
                    action.status = 'executed'
                    action.executed_at = datetime.utcnow()
                except Exception as e:
                    logger.error(f"Failed to execute response action {action.action_id}: {e}")
                    action.status = 'failed'
                finally:
                    self.active_actions.discard(action.action_id)

            db.commit()
            db.close()

        except Exception as e:
            logger.error(f"Failed to process pending responses: {e}")

    async def _execute_response_action(self, action: ResponseAction):
        try:
            handler = self.response_handlers.get(action.action_type)
            if not handler:
                logger.warning(f"No handler for action type: {action.action_type}")
                return

            logger.info(f"Executing response action: {action.action_type} for {action.attacker_ip}")

            success = await handler(action)
            
            if success:
                logger.info(f"Response action executed successfully: {action.action_id}")
            else:
                raise Exception("Response action execution failed")

        except Exception as e:
            logger.error(f"Response action execution failed: {e}")
            raise

    async def _handle_ip_block(self, action: ResponseAction) -> bool:
        try:
            ip_address = action.attacker_ip
            
            if self._is_private_ip(ip_address):
                logger.warning(f"Skipping block for private IP: {ip_address}")
                return True

            iptables_cmd = [
                'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ]
            
            result = subprocess.run(iptables_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully blocked IP: {ip_address}")
                
                action_details = action.action_details or {}
                action_details['iptables_rule_added'] = True
                action_details['block_timestamp'] = datetime.utcnow().isoformat()
                action.action_details = action_details
                
                return True
            else:
                logger.error(f"Failed to block IP {ip_address}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"IP block handling failed: {e}")
            return False

    async def _handle_ip_allow(self, action: ResponseAction) -> bool:
        try:
            ip_address = action.attacker_ip
            
            iptables_cmd = [
                'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ]
            
            result = subprocess.run(iptables_cmd, capture_output=True, text=True)
            
            if result.returncode == 0 or "Bad rule" in result.stderr:
                logger.info(f"Successfully allowed IP: {ip_address}")
                
                action_details = action.action_details or {}
                action_details['iptables_rule_removed'] = True
                action_details['allow_timestamp'] = datetime.utcnow().isoformat()
                action.action_details = action_details
                
                return True
            else:
                logger.error(f"Failed to allow IP {ip_address}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"IP allow handling failed: {e}")
            return False

    async def _handle_quarantine(self, action: ResponseAction) -> bool:
        try:
            logger.info(f"Quarantine action for {action.attacker_ip}")
            
            action_details = action.action_details or {}
            action_details['quarantine_start'] = datetime.utcnow().isoformat()
            action_details['monitoring_enhanced'] = True
            action.action_details = action_details
            
            return True

        except Exception as e:
            logger.error(f"Quarantine handling failed: {e}")
            return False

    async def _handle_alert(self, action: ResponseAction) -> bool:
        try:
            from app.workers.alert_worker import send_immediate_alert
            
            alert_data = {
                'rule_name': 'manual_response_alert',
                'severity': 'high',
                'source_ip': action.attacker_ip,
                'action_type': action.action_type,
                'message': f"Manual response action executed: {action.action_type} for {action.attacker_ip}",
                'timestamp': datetime.utcnow().isoformat()
            }
            
            await send_immediate_alert(alert_data)
            logger.info(f"Alert sent for response action: {action.action_id}")
            
            return True

        except Exception as e:
            logger.error(f"Alert handling failed: {e}")
            return False

    async def _handle_log(self, action: ResponseAction) -> bool:
        try:
            logger.info(f"Log action executed: {action.action_type} for {action.attacker_ip}")
            
            action_details = action.action_details or {}
            action_details['logged_at'] = datetime.utcnow().isoformat()
            action.action_details = action_details
            
            return True

        except Exception as e:
            logger.error(f"Log handling failed: {e}")
            return False

    def _is_private_ip(self, ip_address: str) -> bool:
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except ValueError:
            return False

    async def _cleanup_expired_responses(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            expired_actions = db.query(ResponseAction).filter(
                ResponseAction.status == 'executed',
                ResponseAction.ttl.isnot(None),
                ResponseAction.executed_at <= datetime.utcnow() - timedelta(seconds=ResponseAction.ttl)
            ).all()

            for action in expired_actions:
                try:
                    if action.action_type == 'block_ip':
                        await self._handle_ip_allow(action)
                    
                    action.status = 'expired'
                    logger.info(f"Expired response action: {action.action_id}")

                except Exception as e:
                    logger.error(f"Failed to cleanup response action {action.action_id}: {e}")

            db.commit()
            db.close()

        except Exception as e:
            logger.error(f"Response cleanup failed: {e}")

    async def execute_immediate_response(self, action_data: Dict[str, Any]) -> bool:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            response_action = ResponseAction(
                action_id=f"immediate_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                event_id=action_data.get('event_id', 'manual'),
                attacker_ip=action_data['attacker_ip'],
                action_type=action_data['action_type'],
                action_details=action_data.get('action_details', {}),
                status='executed',
                created_by=action_data.get('created_by', 'system'),
                created_at=datetime.utcnow(),
                executed_at=datetime.utcnow(),
                ttl=action_data.get('ttl', 3600)
            )

            db.add(response_action)
            db.commit()

            success = await self._execute_response_action(response_action)
            
            if not success:
                response_action.status = 'failed'
                db.commit()

            db.close()
            return success

        except Exception as e:
            logger.error(f"Immediate response execution failed: {e}")
            return False

    def get_worker_status(self) -> Dict[str, Any]:
        return {
            'is_running': self.is_running,
            'processing_interval': self.processing_interval,
            'max_concurrent_actions': self.max_concurrent_actions,
            'active_actions_count': len(self.active_actions),
            'response_handlers': list(self.response_handlers.keys()),
            'last_activity': datetime.utcnow().isoformat()
        }

response_worker = ResponseWorker()

async def start_response_worker():
    worker = ResponseWorker()
    await worker.start()
    return worker

async def execute_response_action(action_data: Dict[str, Any]) -> bool:
    worker = ResponseWorker()
    return await worker.execute_immediate_response(action_data)