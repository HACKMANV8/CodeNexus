"""
Alert Background Worker
Manages and sends security alerts and notifications
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.core.database import get_db
from app.models.database_models import AttackEvent, AttackerProfile
from app.core.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

class AlertWorker:
    def __init__(self):
        self.is_running = False
        self.check_interval = 60
        self.alert_cooldown = 300
        self.last_alert_times = {}
        self.alert_rules = self._initialize_alert_rules()

    def _initialize_alert_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'critical_attack',
                'condition': lambda event: event.threat_level == 'critical',
                'severity': 'critical',
                'cooldown': 60,
                'channels': ['email', 'dashboard']
            },
            {
                'name': 'brute_force_detected',
                'condition': lambda event: event.honeypot_type == 'ssh' and event.ml_confidence > 0.8,
                'severity': 'high',
                'cooldown': 300,
                'channels': ['email', 'dashboard']
            },
            {
                'name': 'multiple_attackers',
                'condition': lambda: self._check_multiple_attackers(),
                'severity': 'medium',
                'cooldown': 900,
                'channels': ['dashboard']
            },
            {
                'name': 'new_high_risk_country',
                'condition': lambda event: event.country in ['CN', 'RU', 'KP', 'IR'] and event.threat_level in ['high', 'critical'],
                'severity': 'medium',
                'cooldown': 1800,
                'channels': ['dashboard']
            }
        ]

    async def start(self):
        if self.is_running:
            logger.warning("Alert worker already running")
            return

        self.is_running = True
        logger.info("Starting alert background worker")

        try:
            while self.is_running:
                start_time = datetime.utcnow()
                
                try:
                    await self._check_alerts()
                    await self._cleanup_old_alerts()
                except Exception as e:
                    logger.error(f"Alert worker processing error: {e}")

                processing_time = (datetime.utcnow() - start_time).total_seconds()
                sleep_time = max(1, self.check_interval - processing_time)
                
                await asyncio.sleep(sleep_time)

        except asyncio.CancelledError:
            logger.info("Alert worker stopped")
        except Exception as e:
            logger.error(f"Alert worker crashed: {e}")
        finally:
            self.is_running = False

    async def stop(self):
        self.is_running = False
        logger.info("Stopping alert worker")

    async def _check_alerts(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            recent_events = db.query(AttackEvent).filter(
                AttackEvent.timestamp >= datetime.utcnow() - timedelta(minutes=5),
                AttackEvent.is_malicious == True
            ).all()

            for event in recent_events:
                for rule in self.alert_rules:
                    try:
                        if self._should_trigger_alert(rule, event):
                            await self._trigger_alert(rule, event)
                    except Exception as e:
                        logger.error(f"Alert rule {rule['name']} failed: {e}")

            db.close()

        except Exception as e:
            logger.error(f"Alert check failed: {e}")

    def _should_trigger_alert(self, rule: Dict[str, Any], event: AttackEvent) -> bool:
        rule_key = f"{rule['name']}_{event.source_ip}"
        
        current_time = datetime.utcnow()
        last_alert_time = self.last_alert_times.get(rule_key)
        
        if last_alert_time and (current_time - last_alert_time).total_seconds() < rule['cooldown']:
            return False

        try:
            if 'event' in rule['condition'].__code__.co_varnames:
                return rule['condition'](event)
            else:
                return rule['condition']()
        except Exception as e:
            logger.error(f"Alert condition evaluation failed: {e}")
            return False

    async def _trigger_alert(self, rule: Dict[str, Any], event: AttackEvent):
        rule_key = f"{rule['name']}_{event.source_ip}"
        self.last_alert_times[rule_key] = datetime.utcnow()

        alert_data = {
            'rule_name': rule['name'],
            'severity': rule['severity'],
            'event_id': event.event_id,
            'source_ip': event.source_ip,
            'honeypot_type': event.honeypot_type,
            'threat_level': event.threat_level,
            'confidence': event.ml_confidence,
            'timestamp': datetime.utcnow().isoformat(),
            'message': self._generate_alert_message(rule, event)
        }

        try:
            for channel in rule['channels']:
                if channel == 'email':
                    await self._send_email_alert(alert_data)
                elif channel == 'dashboard':
                    await self._send_dashboard_alert(alert_data)

            logger.info(f"Alert triggered: {rule['name']} for {event.source_ip}")

        except Exception as e:
            logger.error(f"Failed to send alert: {e}")

    def _generate_alert_message(self, rule: Dict[str, Any], event: AttackEvent) -> str:
        messages = {
            'critical_attack': f"Critical attack detected from {event.source_ip} on {event.honeypot_type} honeypot",
            'brute_force_detected': f"SSH brute force attack detected from {event.source_ip} with {event.ml_confidence:.1%} confidence",
            'multiple_attackers': "Multiple attackers detected simultaneously",
            'new_high_risk_country': f"Attack from high-risk country {event.country} detected from {event.source_ip}"
        }
        
        return messages.get(rule['name'], f"Security alert: {rule['name']}")

    async def _send_email_alert(self, alert_data: Dict[str, Any]):
        try:
            smtp_config = getattr(settings, 'smtp', {})
            if not smtp_config.get('enabled', False):
                return

            message = MIMEMultipart()
            message['From'] = smtp_config.get('from_email', 'alerts@honeypot-ctdr.com')
            message['To'] = smtp_config.get('admin_email', 'admin@honeypot-ctdr.com')
            message['Subject'] = f"[{alert_data['severity'].upper()}] Honeypot CTDR Alert: {alert_data['rule_name']}"

            body = f"""
            Security Alert Notification
            
            Rule: {alert_data['rule_name']}
            Severity: {alert_data['severity']}
            Source IP: {alert_data['source_ip']}
            Honeypot: {alert_data['honeypot_type']}
            Threat Level: {alert_data['threat_level']}
            Confidence: {alert_data['confidence']:.1%}
            Time: {alert_data['timestamp']}
            
            Message: {alert_data['message']}
            
            Please review the incident in the Honeypot CTDR dashboard.
            """

            message.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(smtp_config.get('host', 'localhost'), smtp_config.get('port', 587)) as server:
                if smtp_config.get('use_tls', False):
                    server.starttls()
                if smtp_config.get('username') and smtp_config.get('password'):
                    server.login(smtp_config['username'], smtp_config['password'])
                server.send_message(message)

            logger.info(f"Email alert sent for {alert_data['rule_name']}")

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")

    async def _send_dashboard_alert(self, alert_data: Dict[str, Any]):
        try:
            from app.api.websocket import websocket_manager
            
            await websocket_manager.handle_system_metrics({
                'type': 'security_alert',
                'alert_data': alert_data
            })
            
            logger.debug(f"Dashboard alert sent for {alert_data['rule_name']}")

        except Exception as e:
            logger.error(f"Failed to send dashboard alert: {e}")

    def _check_multiple_attackers(self) -> bool:
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            active_attackers = db.query(AttackEvent.source_ip).filter(
                AttackEvent.timestamp >= datetime.utcnow() - timedelta(minutes=5)
            ).distinct().count()

            db.close()

            return active_attackers >= 10

        except Exception as e:
            logger.error(f"Multiple attackers check failed: {e}")
            return False

    async def _cleanup_old_alerts(self):
        current_time = datetime.utcnow()
        keys_to_remove = []
        
        for rule_key, last_alert_time in self.last_alert_times.items():
            if (current_time - last_alert_time).total_seconds() > 86400:
                keys_to_remove.append(rule_key)
        
        for key in keys_to_remove:
            del self.last_alert_times[key]

    async def send_immediate_alert(self, alert_data: Dict[str, Any]):
        try:
            await self._send_email_alert(alert_data)
            await self._send_dashboard_alert(alert_data)
            logger.info(f"Immediate alert sent: {alert_data.get('rule_name', 'custom')}")
        except Exception as e:
            logger.error(f"Failed to send immediate alert: {e}")

    def get_worker_status(self) -> Dict[str, Any]:
        return {
            'is_running': self.is_running,
            'check_interval': self.check_interval,
            'active_alert_rules': len(self.alert_rules),
            'cooldown_entries': len(self.last_alert_times),
            'last_activity': datetime.utcnow().isoformat()
        }

alert_worker = AlertWorker()

async def start_alert_worker():
    worker = AlertWorker()
    await worker.start()
    return worker

async def send_immediate_alert(alert_data: Dict[str, Any]):
    worker = AlertWorker()
    await worker.send_immediate_alert(alert_data)