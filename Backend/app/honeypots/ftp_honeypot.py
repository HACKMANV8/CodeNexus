"""
FTP Honeypot Implementation
Emulates FTP server to capture file transfer attacks and reconnaissance
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.honeypots.base import BaseHoneypot, HoneypotType
from app.core.config import settings

logger = logging.getLogger(__name__)

class FTPHoneypot(BaseHoneypot):
    def __init__(self, port: int = None, config: Dict[str, Any] = None):
        default_config = {
            "banner": "220 Welcome to FTP Server",
            "log_level": "INFO",
            "max_connections": 50,
            "fake_files": [
                "/backup.tar.gz", "/database.sql", "/config.ini",
                "/passwords.txt", "/secrets.zip"
            ],
            "fake_users": ["anonymous", "ftp", "admin", "test"],
            "max_login_attempts": 3,
            "allow_anonymous": True
        }
        
        final_config = {**default_config, **(config or {})}
        final_port = port or settings.ftp_honeypot_port
        
        super().__init__(HoneypotType.FTP, final_port, final_config)
        
        self.server = None
        self.active_connections = set()
        self.user_sessions = {}

    async def start(self):
        if self.is_running:
            logger.warning("FTP honeypot already running")
            return

        try:
            self.server = await asyncio.start_server(
                self._handle_client,
                host='0.0.0.0',
                port=self.port
            )

            self.is_running = True
            self.stats["start_time"] = datetime.utcnow()
            
            logger.info(f"FTP honeypot started on port {self.port}")
            
            async with self.server:
                await self.server.serve_forever()
                
        except Exception as e:
            logger.error(f"Failed to start FTP honeypot: {e}")
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
        self.user_sessions.clear()
        logger.info("FTP honeypot stopped")

    async def handle_connection(self, client_info: Dict[str, Any]):
        reader = client_info.get("reader")
        writer = client_info.get("writer")
        
        if not reader or not writer:
            return

        self.active_connections.add(writer)
        session_id = id(writer)
        
        try:
            await self._send_response(writer, self.config["banner"])
            
            authenticated = False
            login_attempts = 0
            
            while not authenticated and login_attempts < self.config["max_login_attempts"]:
                data = await reader.read(1024)
                if not data:
                    break
                    
                command = data.decode('utf-8', errors='ignore').strip()
                response, authenticated = await self._handle_ftp_command(command, session_id, client_info)
                
                if response:
                    await self._send_response(writer, response)
                    
                login_attempts += 1
                
            if authenticated:
                await self._handle_authenticated_session(reader, writer, session_id, client_info)
                
        except Exception as e:
            logger.error(f"FTP connection handling error: {e}")
        finally:
            self.active_connections.discard(writer)
            if session_id in self.user_sessions:
                del self.user_sessions[session_id]
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def _handle_ftp_command(self, command: str, session_id: int, client_info: Dict[str, Any]) -> tuple:
        command_upper = command.upper()
        
        if command_upper.startswith('USER'):
            username = command[5:].strip()
            self.user_sessions[session_id] = {"username": username, "authenticated": False}
            
            event_data = {
                "source_ip": client_info["source_ip"],
                "source_port": client_info["source_port"],
                "destination_port": self.port,
                "payload": f"USER {username}",
                "is_malicious": username in self.config["fake_users"],
                "tags": ["ftp_user_command", f"username_{username}"]
            }
            await self.log_event(event_data)
            
            return "331 Password required", False
            
        elif command_upper.startswith('PASS'):
            password = command[5:].strip()
            session = self.user_sessions.get(session_id, {})
            username = session.get("username", "unknown")
            
            event_data = {
                "source_ip": client_info["source_ip"],
                "source_port": client_info["source_port"],
                "destination_port": self.port,
                "payload": f"PASS {password}",
                "username": username,
                "is_malicious": True,
                "tags": ["ftp_password_attempt", "authentication_attack"]
            }
            await self.log_event(event_data)
            
            if self.config["allow_anonymous"] and username.lower() == "anonymous":
                self.user_sessions[session_id]["authenticated"] = True
                return "230 Login successful", True
            else:
                return "530 Login incorrect", False
                
        elif command_upper.startswith('SYST'):
            return "215 UNIX Type: L8", False
            
        elif command_upper.startswith('FEAT'):
            return "211 End", False
            
        elif command_upper.startswith('PWD'):
            return '257 "/" is current directory', False
            
        elif command_upper.startswith('TYPE'):
            return "200 Type set to I", False
            
        elif command_upper.startswith('PASV'):
            return "227 Entering Passive Mode (127,0,0,1,100,100)", False
            
        elif command_upper.startswith('LIST'):
            event_data = {
                "source_ip": client_info["source_ip"],
                "source_port": client_info["source_port"],
                "destination_port": self.port,
                "payload": "LIST",
                "is_malicious": True,
                "tags": ["ftp_directory_listing", "reconnaissance"]
            }
            await self.log_event(event_data)
            
            file_list = "\r\n".join([f"-rw-r--r-- 1 ftp ftp 1024 Jan 1 00:00 {f}" for f in self.config["fake_files"]])
            return f"150 Opening data connection\r\n{file_list}\r\n226 Transfer complete", False
            
        elif command_upper.startswith('RETR'):
            filename = command[5:].strip()
            event_data = {
                "source_ip": client_info["source_ip"],
                "source_port": client_info["source_port"],
                "destination_port": self.port,
                "payload": f"RETR {filename}",
                "is_malicious": True,
                "tags": ["ftp_file_download", "data_exfiltration_attempt"]
            }
            await self.log_event(event_data)
            
            return "550 Failed to open file", False
            
        elif command_upper.startswith('STOR'):
            filename = command[5:].strip()
            event_data = {
                "source_ip": client_info["source_ip"],
                "source_port": client_info["source_port"],
                "destination_port": self.port,
                "payload": f"STOR {filename}",
                "is_malicious": True,
                "tags": ["ftp_file_upload", "malware_upload_attempt"]
            }
            await self.log_event(event_data)
            
            return "553 Could not create file", False
            
        else:
            event_data = {
                "source_ip": client_info["source_ip"],
                "source_port": client_info["source_port"],
                "destination_port": self.port,
                "payload": command,
                "tags": ["ftp_command"]
            }
            await self.log_event(event_data)
            
            return "502 Command not implemented", False

    async def _handle_authenticated_session(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session_id: int, client_info: Dict[str, Any]):
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                    
                command = data.decode('utf-8', errors='ignore').strip()
                response, _ = await self._handle_ftp_command(command, session_id, client_info)
                
                if response:
                    await self._send_response(writer, response)
                    
        except Exception as e:
            logger.debug(f"FTP authenticated session error: {e}")

    async def _send_response(self, writer, response: str):
        if not response.endswith('\r\n'):
            response += '\r\n'
        writer.write(response.encode())
        await writer.drain()

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
            "active_sessions": len(self.user_sessions),
            "fake_files": self.config["fake_files"],
            "fake_users": self.config["fake_users"],
            "allow_anonymous": self.config["allow_anonymous"]
        })
        return base_stats