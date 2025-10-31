"""
Base Honeypot Class and Common Functionality
"""

import logging
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from enum import Enum
from datetime import datetime

from app.pipeline.ingest import ingest_attack_event

logger = logging.getLogger(__name__)

class HoneypotType(Enum):
    SSH = "ssh"
    WEB = "web"
    FTP = "ftp"
    URL_TRAP = "url_trap"

class BaseHoneypot(ABC):
    def __init__(self, honeypot_type: HoneypotType, port: int, config: Dict[str, Any]):
        self.honeypot_type = honeypot_type
        self.port = port
        self.config = config
        self.is_running = False
        self.stats = {
            "connections": 0,
            "attacks_detected": 0,
            "start_time": None,
            "last_activity": None
        }

    @abstractmethod
    async def start(self):
        pass

    @abstractmethod
    async def stop(self):
        pass

    @abstractmethod
    async def handle_connection(self, client_info: Dict[str, Any]):
        pass

    async def log_event(self, event_data: Dict[str, Any]):
        try:
            event_data.update({
                "honeypot_type": self.honeypot_type.value,
                "timestamp": datetime.utcnow()
            })

            await ingest_attack_event(self.honeypot_type.value, event_data["source_ip"], event_data)

            self.stats["connections"] += 1
            self.stats["last_activity"] = datetime.utcnow()

            if event_data.get("is_malicious", False):
                self.stats["attacks_detected"] += 1

            logger.info(f"Honeypot event: {self.honeypot_type.value} from {event_data['source_ip']}")

        except Exception as e:
            logger.error(f"Failed to log honeypot event: {e}")

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": self.honeypot_type.value,
            "port": self.port,
            "is_running": self.is_running,
            "stats": self.stats,
            "config": self.config
        }

    def validate_config(self) -> bool:
        required_fields = ["banner", "log_level", "max_connections"]
        return all(field in self.config for field in required_fields)

    async def health_check(self) -> Dict[str, Any]:
        return {
            "status": "healthy" if self.is_running else "stopped",
            "uptime": self._calculate_uptime(),
            "connections": self.stats["connections"],
            "attacks_detected": self.stats["attacks_detected"]
        }

    def _calculate_uptime(self) -> Optional[float]:
        if not self.stats["start_time"]:
            return None
        return (datetime.utcnow() - self.stats["start_time"]).total_seconds()

    def _extract_client_info(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Dict[str, Any]:
        client_addr = writer.get_extra_info('peername')
        return {
            "source_ip": client_addr[0] if client_addr else "unknown",
            "source_port": client_addr[1] if client_addr else 0,
            "destination_port": self.port,
            "timestamp": datetime.utcnow()
        }