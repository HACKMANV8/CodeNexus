"""
Honeypot CTDR - Honeypots Module
Multi-service honeypots for threat detection and intelligence gathering
"""

from app.honeypots.base import BaseHoneypot, HoneypotType
from app.honeypots.ssh_honeypot import SSHHoneypot
from app.honeypots.web_honeypot import WebHoneypot
from app.honeypots.url_trap import URLTrapHoneypot
from app.honeypots.ftp_honeypot import FTPHoneypot
from app.honeypots.factory import HoneypotFactory
from app.honeypots.deception_engine import DeceptionEngine

from app.honeypots.factory import create_honeypot, start_all_honeypots, stop_all_honeypots
from app.honeypots.deception_engine import generate_deceptive_content, create_decoy_service

__all__ = [
    "BaseHoneypot",
    "HoneypotType",
    "SSHHoneypot", 
    "WebHoneypot",
    "URLTrapHoneypot",
    "FTPHoneypot",
    "HoneypotFactory",
    "DeceptionEngine",
    "create_honeypot",
    "start_all_honeypots", 
    "stop_all_honeypots",
    "generate_deceptive_content",
    "create_decoy_service"
]