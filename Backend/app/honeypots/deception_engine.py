"""
Deception Engine
Generates realistic deceptive content and services
"""

import logging
import random
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class DeceptionEngine:
    def __init__(self):
        self.deceptive_content = self._initialize_deceptive_content()
        self.service_templates = self._initialize_service_templates()
        self.entropy_level = "medium"

    def _initialize_deceptive_content(self) -> Dict[str, Any]:
        return {
            "web_pages": {
                "login": [
                    """
                    <html>
                    <head><title>Admin Login</title></head>
                    <body>
                        <h1>Administrator Login</h1>
                        <form method="post" action="/login">
                            <input type="text" name="username" placeholder="Username">
                            <input type="password" name="password" placeholder="Password">
                            <button type="submit">Login</button>
                        </form>
                    </body>
                    </html>
                    """,
                    """
                    <html>
                    <head><title>Secure Access Portal</title></head>
                    <body>
                        <h2>Secure Access Required</h2>
                        <form method="post">
                            <div>Username: <input type="text" name="user"></div>
                            <div>Password: <input type="password" name="pass"></div>
                            <input type="submit" value="Authenticate">
                        </form>
                    </body>
                    </html>
                    """
                ],
                "error": [
                    """
                    <html>
                    <head><title>404 Not Found</title></head>
                    <body>
                        <h1>404 Not Found</h1>
                        <p>The requested URL was not found on this server.</p>
                        <hr>
                        <address>Apache/2.4.41 (Ubuntu) Server</address>
                    </body>
                    </html>
                    """,
                    """
                    <html>
                    <head><title>500 Internal Server Error</title></head>
                    <body>
                        <h1>Internal Server Error</h1>
                        <p>The server encountered an internal error and could not complete your request.</p>
                    </body>
                    </html>
                    """
                ],
                "api_response": [
                    '{"status": "error", "message": "Authentication required"}',
                    '{"error": "Invalid API key", "code": 401}',
                    '{"result": "success", "data": {"user": "admin", "role": "administrator"}}'
                ]
            },
            "ssh_banners": [
                "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
                "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
                "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"
            ],
            "ftp_responses": {
                "welcome": "220 Welcome to FTP Server",
                "login_success": "230 Login successful",
                "login_failed": "530 Login incorrect",
                "file_not_found": "550 Failed to open file"
            },
            "fake_data": {
                "usernames": ["admin", "root", "test", "user", "administrator", "guest"],
                "passwords": ["password", "123456", "admin", "test", "guest", "default"],
                "filenames": ["backup.tar.gz", "database.sql", "config.ini", "passwords.txt"],
                "directories": ["/var/www", "/etc", "/home", "/tmp", "/backup"]
            }
        }

    def _initialize_service_templates(self) -> Dict[str, Any]:
        return {
            "web_server": {
                "headers": {
                    "Server": ["Apache/2.4.41", "nginx/1.18.0", "Microsoft-IIS/10.0"],
                    "X-Powered-By": ["PHP/7.4.3", "ASP.NET", "Node.js"]
                },
                "status_codes": [200, 301, 302, 404, 500]
            },
            "database_server": {
                "error_messages": [
                    "Connection refused", "Access denied", "Table doesn't exist",
                    "Syntax error", "Too many connections"
                ]
            },
            "file_server": {
                "file_listings": [
                    "-rw-r--r-- 1 ftp ftp 1024 Jan 1 00:00 backup.zip",
                    "-rw-r--r-- 1 ftp ftp 2048 Jan 1 00:00 database.sql",
                    "drwxr-xr-x 2 ftp ftp 4096 Jan 1 00:00 logs"
                ]
            }
        }

    def generate_deceptive_content(self, content_type: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        context = context or {}
        
        if content_type == "web_page":
            return self._generate_web_page(context)
        elif content_type == "ssh_banner":
            return self._generate_ssh_banner()
        elif content_type == "ftp_response":
            return self._generate_ftp_response(context)
        elif content_type == "api_response":
            return self._generate_api_response(context)
        else:
            return {"content": "Not implemented", "status_code": 501}

    def _generate_web_page(self, context: Dict[str, Any]) -> Dict[str, Any]:
        page_type = context.get("page_type", "login")
        templates = self.deceptive_content["web_pages"].get(page_type, [""])
        
        content = random.choice(templates)
        headers = {
            "Server": random.choice(self.service_templates["web_server"]["headers"]["Server"]),
            "X-Powered-By": random.choice(self.service_templates["web_server"]["headers"]["X-Powered-By"]),
            "Content-Type": "text/html"
        }
        
        status_code = 200
        if page_type == "error":
            status_code = random.choice([404, 500])
        
        return {
            "content": content,
            "headers": headers,
            "status_code": status_code
        }

    def _generate_ssh_banner(self) -> Dict[str, Any]:
        banner = random.choice(self.deceptive_content["ssh_banners"])
        return {
            "content": banner,
            "headers": {},
            "status_code": None
        }

    def _generate_ftp_response(self, context: Dict[str, Any]) -> Dict[str, Any]:
        response_type = context.get("response_type", "welcome")
        response_content = self.deceptive_content["ftp_responses"].get(response_type, "")
        
        return {
            "content": response_content,
            "headers": {},
            "status_code": None
        }

    def _generate_api_response(self, context: Dict[str, Any]) -> Dict[str, Any]:
        templates = self.deceptive_content["web_pages"]["api_response"]
        content = random.choice(templates)
        
        headers = {
            "Content-Type": "application/json",
            "Server": random.choice(self.service_templates["web_server"]["headers"]["Server"])
        }
        
        return {
            "content": content,
            "headers": headers,
            "status_code": 200
        }

    def create_decoy_service(self, service_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        decoy_service = {
            "type": service_type,
            "created_at": datetime.utcnow(),
            "entropy_level": self.entropy_level,
            "realism_score": self._calculate_realism_score(service_type),
            "interaction_points": []
        }
        
        if service_type == "web_application":
            decoy_service.update(self._create_web_decoy(config))
        elif service_type == "database_server":
            decoy_service.update(self._create_database_decoy(config))
        elif service_type == "file_server":
            decoy_service.update(self._create_file_decoy(config))
        
        return decoy_service

    def _create_web_decoy(self, config: Dict[str, Any]) -> Dict[str, Any]:
        endpoints = config.get("endpoints", ["/admin", "/api", "/login"])
        
        return {
            "endpoints": [
                {
                    "path": endpoint,
                    "methods": ["GET", "POST"],
                    "response_type": "html" if "login" in endpoint else "json",
                    "entropy": random.uniform(0.6, 0.9)
                }
                for endpoint in endpoints
            ],
            "headers": self.service_templates["web_server"]["headers"],
            "fake_credentials": [
                {"username": user, "password": passwd}
                for user, passwd in zip(
                    self.deceptive_content["fake_data"]["usernames"],
                    self.deceptive_content["fake_data"]["passwords"]
                )
            ]
        }

    def _create_database_decoy(self, config: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "error_messages": self.service_templates["database_server"]["error_messages"],
            "fake_tables": ["users", "config", "sessions", "logs"],
            "response_delay": random.uniform(0.1, 0.5)
        }

    def _create_file_decoy(self, config: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "file_listings": self.service_templates["file_server"]["file_listings"],
            "fake_files": self.deceptive_content["fake_data"]["filenames"],
            "directories": self.deceptive_content["fake_data"]["directories"]
        }

    def _calculate_realism_score(self, service_type: str) -> float:
        base_scores = {
            "web_application": 0.85,
            "database_server": 0.75,
            "file_server": 0.80
        }
        return base_scores.get(service_type, 0.5)

    def increase_entropy(self):
        entropy_levels = ["low", "medium", "high"]
        current_index = entropy_levels.index(self.entropy_level)
        if current_index < len(entropy_levels) - 1:
            self.entropy_level = entropy_levels[current_index + 1]

    def decrease_entropy(self):
        entropy_levels = ["low", "medium", "high"]
        current_index = entropy_levels.index(self.entropy_level)
        if current_index > 0:
            self.entropy_level = entropy_levels[current_index - 1]

    def get_entropy_level(self) -> str:
        return self.entropy_level

    def generate_fake_credentials(self, count: int = 5) -> List[Dict[str, str]]:
        usernames = random.sample(self.deceptive_content["fake_data"]["usernames"], 
                                 min(count, len(self.deceptive_content["fake_data"]["usernames"])))
        passwords = random.sample(self.deceptive_content["fake_data"]["passwords"], 
                                 min(count, len(self.deceptive_content["fake_data"]["passwords"])))
        
        return [{"username": u, "password": p} for u, p in zip(usernames, passwords)]

def generate_deceptive_content(content_type: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    engine = DeceptionEngine()
    return engine.generate_deceptive_content(content_type, context)

def create_decoy_service(service_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
    engine = DeceptionEngine()
    return engine.create_decoy_service(service_type, config)