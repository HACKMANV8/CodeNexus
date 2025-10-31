"""
Logging Utilities
Centralized logging configuration and management
"""

import logging
import logging.handlers
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from app.core.config import settings

class CustomFormatter(logging.Formatter):
    def __init__(self):
        super().__init__()
        self.default_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.error_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )

    def format(self, record):
        if record.levelno >= logging.ERROR:
            return self.error_formatter.format(record)
        else:
            return self.default_formatter.format(record)

def setup_logging(
    name: str = "honeypot_ctdr",
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    max_bytes: int = 10485760,
    backup_count: int = 5
) -> logging.Logger:
    logger = logging.getLogger(name)
    
    if logger.handlers:
        return logger

    try:
        log_level = getattr(logging, log_level.upper(), logging.INFO)
        logger.setLevel(log_level)

        formatter = CustomFormatter()

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        logger.propagate = False
        
        return logger

    except Exception as e:
        print(f"Failed to setup logging: {e}")
        fallback_logger = logging.getLogger("fallback")
        if not fallback_logger.handlers:
            logging.basicConfig(level=logging.INFO)
        return fallback_logger

def get_logger(module_name: str) -> logging.Logger:
    logger_name = f"honeypot_ctdr.{module_name}"
    return logging.getLogger(logger_name)

def log_system_event(
    logger: logging.Logger,
    event_type: str,
    message: str,
    level: str = "INFO",
    extra_data: Optional[Dict[str, Any]] = None
):
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    log_message = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "message": message,
        "extra_data": extra_data or {}
    }
    
    if log_level == logging.DEBUG:
        logger.debug(log_message)
    elif log_level == logging.INFO:
        logger.info(log_message)
    elif log_level == logging.WARNING:
        logger.warning(log_message)
    elif log_level == logging.ERROR:
        logger.error(log_message)
    elif log_level == logging.CRITICAL:
        logger.critical(log_message)
    else:
        logger.info(log_message)

class AuditLogger:
    def __init__(self):
        self.logger = get_logger("audit")
        self.audit_file = settings.LOGS_DIR / "audit.log"

    def log_auth_event(self, username: str, event: str, success: bool, ip_address: str = None):
        audit_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "authentication",
            "username": username,
            "action": event,
            "success": success,
            "ip_address": ip_address,
            "user_agent": None
        }
        
        self.logger.info(f"AUTH: {username} - {event} - Success: {success} - IP: {ip_address}")

    def log_security_event(self, event: str, severity: str, details: Dict[str, Any]):
        audit_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "security",
            "severity": severity,
            "details": details
        }
        
        self.logger.warning(f"SECURITY: {event} - Severity: {severity} - Details: {details}")

    def log_system_event(self, component: str, event: str, status: str, details: Dict[str, Any] = None):
        audit_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "system",
            "component": component,
            "action": event,
            "status": status,
            "details": details or {}
        }
        
        self.logger.info(f"SYSTEM: {component} - {event} - Status: {status}")

    def log_data_access(self, user: str, resource: str, action: str, success: bool):
        audit_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "data_access",
            "user": user,
            "resource": resource,
            "action": action,
            "success": success
        }
        
        self.logger.info(f"DATA_ACCESS: {user} - {action} - {resource} - Success: {success}")

def get_audit_logger() -> AuditLogger:
    return AuditLogger()

def configure_application_logging():
    log_file = settings.LOGS_DIR / "application.log"
    return setup_logging(
        name="honeypot_ctdr",
        log_level=settings.honeypot_log_level,
        log_file=str(log_file),
        max_bytes=10485760,
        backup_count=10
    )

def configure_security_logging():
    log_file = settings.LOGS_DIR / "security.log"
    return setup_logging(
        name="security",
        log_level="INFO",
        log_file=str(log_file),
        max_bytes=5242880,
        backup_count=5
    )