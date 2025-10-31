"""
Web Application Honeypot Implementation
Emulates web services to capture web-based attacks
"""

import asyncio
from aiohttp import web
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import json

from app.honeypots.base import BaseHoneypot, HoneypotType
from app.core.config import settings
from app.honeypots.deception_engine import generate_deceptive_content

logger = logging.getLogger(__name__)

class WebHoneypot(BaseHoneypot):
    def __init__(self, port: int = None, config: Dict[str, Any] = None):
        default_config = {
            "banner": "Apache/2.4.41 (Ubuntu)",
            "log_level": "INFO",
            "max_connections": 1000,
            "fake_endpoints": [
                "/admin", "/phpmyadmin", "/wp-admin", "/config",
                "/backup", "/database", "/.env", "/api/v1/users"
            ],
            "fake_technologies": ["PHP/7.4", "MySQL", "WordPress/5.8"],
            "response_delay": 0.1
        }
        
        final_config = {**default_config, **(config or {})}
        final_port = port or settings.web_honeypot_port
        
        super().__init__(HoneypotType.WEB, final_port, final_config)
        
        self.app = None
        self.runner = None
        self.site = None

    async def start(self):
        if self.is_running:
            logger.warning("Web honeypot already running")
            return

        try:
            self.app = web.Application()
            self._setup_routes()
            
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            
            self.site = web.TCPSite(self.runner, '0.0.0.0', self.port)
            await self.site.start()
            
            self.is_running = True
            self.stats["start_time"] = datetime.utcnow()
            
            logger.info(f"Web honeypot started on port {self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start web honeypot: {e}")
            self.is_running = False

    async def stop(self):
        if not self.is_running:
            return

        self.is_running = False
        
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
            
        logger.info("Web honeypot stopped")

    async def handle_connection(self, client_info: Dict[str, Any]):
        pass

    def _setup_routes(self):
        self.app.router.add_route('*', '/', self._handle_root)
        self.app.router.add_route('*', '/{path:.*}', self._handle_catch_all)
        
        for endpoint in self.config["fake_endpoints"]:
            self.app.router.add_route('*', endpoint, self._handle_fake_endpoint)

    async def _handle_root(self, request):
        return await self._process_web_request(request, "root")

    async def _handle_fake_endpoint(self, request):
        endpoint = request.path
        return await self._process_web_request(request, f"fake_endpoint:{endpoint}")

    async def _handle_catch_all(self, request):
        return await self._process_web_request(request, "catch_all")

    async def _process_web_request(self, request, endpoint_type: str):
        client_ip = request.remote
        method = request.method
        path = request.path
        user_agent = request.headers.get('User-Agent', '')
        headers = dict(request.headers)
        
        if self.config["response_delay"] > 0:
            await asyncio.sleep(self.config["response_delay"])
        
        payload = await self._extract_payload(request)
        
        event_data = {
            "source_ip": client_ip,
            "destination_port": self.port,
            "method": method,
            "url": path,
            "user_agent": user_agent,
            "headers": headers,
            "payload": payload,
            "endpoint_type": endpoint_type,
            "is_malicious": self._is_malicious_request(method, path, payload, user_agent),
            "tags": self._generate_tags(method, path, payload, user_agent)
        }
        
        await self.log_event(event_data)
        
        response_data = generate_deceptive_content("web", path, method)
        return web.Response(
            text=response_data.get("content", "Not Found"),
            status=response_data.get("status_code", 200),
            headers=response_data.get("headers", {})
        )

    async def _extract_payload(self, request):
        payload = {}
        
        try:
            if request.can_read_body:
                body = await request.text()
                if body:
                    payload["body"] = body
            
            if request.query_string:
                payload["query_params"] = dict(request.query)
                
            if request.headers.get('Content-Type') == 'application/json' and 'body' in payload:
                try:
                    payload["json_body"] = json.loads(payload["body"])
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"Payload extraction error: {e}")
            
        return payload

    def _is_malicious_request(self, method: str, path: str, payload: Dict[str, Any], user_agent: str) -> bool:
        malicious_indicators = [
            "../" in path,
            "etc/passwd" in path,
            "union select" in str(payload).lower(),
            "<script>" in str(payload).lower(),
            "nmap" in user_agent.lower(),
            "sqlmap" in user_agent.lower(),
            method in ["PUT", "DELETE", "PATCH"] and "/api/" in path
        ]
        
        return any(malicious_indicators)

    def _generate_tags(self, method: str, path: str, payload: Dict[str, Any], user_agent: str) -> List[str]:
        tags = ["web_request", f"method_{method.lower()}"]
        
        if any(x in path for x in [".php", ".asp", ".jsp"]):
            tags.append("dynamic_content_request")
            
        if "admin" in path.lower():
            tags.append("admin_access_attempt")
            
        if any(tool in user_agent.lower() for tool in ["nmap", "sqlmap", "metasploit"]):
            tags.append("scanner_tool")
            
        if self._is_malicious_request(method, path, payload, user_agent):
            tags.append("malicious_attempt")
            
        return tags

    def get_detailed_stats(self) -> Dict[str, Any]:
        base_stats = self.get_stats()
        base_stats.update({
            "fake_endpoints": self.config["fake_endpoints"],
            "fake_technologies": self.config["fake_technologies"],
            "response_delay": self.config["response_delay"]
        })
        return base_stats