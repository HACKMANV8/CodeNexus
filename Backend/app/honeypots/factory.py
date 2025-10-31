"""
Honeypot Factory
Manages creation and lifecycle of all honeypot instances
"""

import logging
from typing import Dict, Any, List, Optional
from enum import Enum

from app.honeypots.base import BaseHoneypot, HoneypotType
from app.honeypots.ssh_honeypot import SSHHoneypot
from app.honeypots.web_honeypot import WebHoneypot
from app.honeypots.url_trap import URLTrapHoneypot
from app.honeypots.ftp_honeypot import FTPHoneypot
from app.core.config import settings

logger = logging.getLogger(__name__)

class HoneypotFactory:
    def __init__(self):
        self.honeypots: Dict[HoneypotType, BaseHoneypot] = {}
        self._initialize_honeypots()

    def _initialize_honeypots(self):
        honeypot_configs = {
            HoneypotType.SSH: {
                "port": settings.ssh_honeypot_port,
                "config": {
                    "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
                    "max_connections": 100,
                    "fake_users": ["admin", "root", "test", "user"],
                    "max_auth_attempts": 3
                }
            },
            HoneypotType.WEB: {
                "port": settings.web_honeypot_port,
                "config": {
                    "banner": "Apache/2.4.41 (Ubuntu)",
                    "max_connections": 1000,
                    "fake_endpoints": [
                        "/admin", "/phpmyadmin", "/wp-admin", "/config",
                        "/backup", "/database", "/.env", "/api/v1/users"
                    ],
                    "response_delay": 0.1
                }
            },
            HoneypotType.URL_TRAP: {
                "port": settings.web_honeypot_port + 100,
                "config": {
                    "banner": "nginx/1.18.0 (Ubuntu)",
                    "max_connections": 500,
                    "trap_urls": [
                        "/login.php", "/admin.php", "/wp-login.php",
                        "/api/v1/auth", "/.git/config", "/backup.zip"
                    ]
                }
            },
            HoneypotType.FTP: {
                "port": settings.ftp_honeypot_port,
                "config": {
                    "banner": "220 Welcome to FTP Server",
                    "max_connections": 50,
                    "fake_files": [
                        "/backup.tar.gz", "/database.sql", "/config.ini",
                        "/passwords.txt", "/secrets.zip"
                    ],
                    "allow_anonymous": True
                }
            }
        }

        for honeypot_type, config in honeypot_configs.items():
            self.honeypots[honeypot_type] = self._create_honeypot(honeypot_type, config)

    def _create_honeypot(self, honeypot_type: HoneypotType, config: Dict[str, Any]) -> BaseHoneypot:
        honeypot_class = {
            HoneypotType.SSH: SSHHoneypot,
            HoneypotType.WEB: WebHoneypot,
            HoneypotType.URL_TRAP: URLTrapHoneypot,
            HoneypotType.FTP: FTPHoneypot
        }.get(honeypot_type)

        if not honeypot_class:
            raise ValueError(f"Unsupported honeypot type: {honeypot_type}")

        return honeypot_class(port=config["port"], config=config["config"])

    async def start_all_honeypots(self):
        logger.info("Starting all honeypots...")
        
        for honeypot_type, honeypot in self.honeypots.items():
            try:
                await honeypot.start()
                logger.info(f"Started {honeypot_type.value} honeypot on port {honeypot.port}")
            except Exception as e:
                logger.error(f"Failed to start {honeypot_type.value} honeypot: {e}")

    async def stop_all_honeypots(self):
        logger.info("Stopping all honeypots...")
        
        for honeypot_type, honeypot in self.honeypots.items():
            try:
                await honeypot.stop()
                logger.info(f"Stopped {honeypot_type.value} honeypot")
            except Exception as e:
                logger.error(f"Failed to stop {honeypot_type.value} honeypot: {e}")

    async def start_honeypot(self, honeypot_type: HoneypotType):
        honeypot = self.honeypots.get(honeypot_type)
        if honeypot:
            await honeypot.start()
        else:
            logger.error(f"Honeypot type not found: {honeypot_type}")

    async def stop_honeypot(self, honeypot_type: HoneypotType):
        honeypot = self.honeypots.get(honeypot_type)
        if honeypot:
            await honeypot.stop()
        else:
            logger.error(f"Honeypot type not found: {honeypot_type}")

    def get_honeypot(self, honeypot_type: HoneypotType) -> Optional[BaseHoneypot]:
        return self.honeypots.get(honeypot_type)

    def get_all_honeypots(self) -> List[BaseHoneypot]:
        return list(self.honeypots.values())

    def get_honeypot_stats(self) -> Dict[str, Any]:
        stats = {}
        
        for honeypot_type, honeypot in self.honeypots.items():
            stats[honeypot_type.value] = honeypot.get_stats()
            
        return stats

    def get_detailed_stats(self) -> Dict[str, Any]:
        detailed_stats = {}
        
        for honeypot_type, honeypot in self.honeypots.items():
            if hasattr(honeypot, 'get_detailed_stats'):
                detailed_stats[honeypot_type.value] = honeypot.get_detailed_stats()
            else:
                detailed_stats[honeypot_type.value] = honeypot.get_stats()
                
        return detailed_stats

    async def health_check(self) -> Dict[str, Any]:
        health_status = {}
        
        for honeypot_type, honeypot in self.honeypots.items():
            health_status[honeypot_type.value] = await honeypot.health_check()
            
        return health_status

def create_honeypot(honeypot_type: HoneypotType, port: int, config: Dict[str, Any]) -> BaseHoneypot:
    factory = HoneypotFactory()
    return factory._create_honeypot(honeypot_type, {"port": port, "config": config})

async def start_all_honeypots():
    factory = HoneypotFactory()
    await factory.start_all_honeypots()
    return factory

async def stop_all_honeypots():
    factory = HoneypotFactory()
    await factory.stop_all_honeypots()