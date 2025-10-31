"""
SSH Honeypot Implementation
Emulates SSH server to capture brute force attacks and reconnaissance
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from app.honeypots.base import BaseHoneypot, HoneypotType
from app.core.config import settings

logger = logging.getLogger(__name__)

class SSHHoneypot(BaseHoneypot):
    def __init__(self, port: int = None, config: Dict[str, Any] = None):
        default_config = {
            "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
            "log_level": "INFO",
            "max_connections": 100,
            "fake_users": ["admin", "root", "test", "user"],
            "fake_passwords": ["password", "123456", "admin", "test"],
            "max_auth_attempts": 3
        }
        
        final_config = {**default_config, **(config or {})}
        final_port = port or settings.ssh_honeypot_port
        
        super().__init__(HoneypotType.SSH, final_port, final_config)
        
        self.server = None
        self.active_connections = set()

    async def start(self):
        if self.is_running:
            logger.warning("SSH honeypot already running")
            return

        try:
            self.server = await asyncio.start_server(
                self._handle_client,
                host='0.0.0.0',
                port=self.port
            )

            self.is_running = True
            self.stats["start_time"] = datetime.utcnow()
            
            logger.info(f"SSH honeypot started on port {self.port}")
            
            async with self.server:
                await self.server.serve_forever()
                
        except Exception as e:
            logger.error(f"Failed to start SSH honeypot: {e}")
            self.is_running = False

    async def stop(self):
        if not self.is_running:
            return

        self.is_running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            
        for writer in self.active_connections:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
                
        self.active_connections.clear()
        logger.info("SSH honeypot stopped")

    async def handle_connection(self, client_info: Dict[str, Any]):
        reader = client_info.get("reader")
        writer = client_info.get("writer")
        
        if not reader or not writer:
            return

        self.active_connections.add(writer)
        
        try:
            await self._send_banner(writer)
            
            auth_attempts = 0
            max_attempts = self.config["max_auth_attempts"]
            
            while auth_attempts < max_attempts:
                data = await reader.read(1024)
                if not data:
                    break
                    
                auth_attempts += 1
                await self._handle_ssh_data(data, client_info, auth_attempts)
                
            if auth_attempts >= max_attempts:
                event_data = {
                    "source_ip": client_info["source_ip"],
                    "source_port": client_info["source_port"],
                    "destination_port": self.port,
                    "payload": f"SSH brute force detected: {auth_attempts} attempts",
                    "is_malicious": True,
                    "tags": ["ssh_brute_force", "authentication_attack"]
                }
                await self.log_event(event_data)
                
        except Exception as e:
            logger.error(f"SSH connection handling error: {e}")
        finally:
            self.active_connections.discard(writer)
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def _send_banner(self, writer):
        banner = self.config["banner"] + "\r\n"
        writer.write(banner.encode())
        await writer.drain()

    async def _handle_ssh_data(self, data: bytes, client_info: Dict[str, Any], attempt: int):
        try:
            payload = data.decode('utf-8', errors='ignore')
            
            event_data = {
                "source_ip": client_info["source_ip"],
                "source_port": client_info["source_port"],
                "destination_port": self.port,
                "payload": payload,
                "attempt_number": attempt,
                "is_malicious": True,
                "tags": ["ssh_authentication_attempt"]
            }
            
            if "root" in payload.lower() or "admin" in payload.lower():
                event_data["tags"].append("privileged_account_targeted")
                
            await self.log_event(event_data)
            
        except Exception as e:
            logger.error(f"SSH data handling error: {e}")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_info = self._extract_client_info(reader, writer)
        await self.handle_connection({
            "reader": reader,
            "writer": writer,
            **client_info
        })

    def get_detailed_stats(self) -> Dict[str, Any]:
        base_stats = self.get_stats()
        base_stats.update({
            "active_connections": len(self.active_connections),
            "fake_users": self.config["fake_users"],
            "max_auth_attempts": self.config["max_auth_attempts"]
        })
        return base_stats