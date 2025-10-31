"""
URL Trap Honeypot Implementation
Captures malicious URL clicks and phishing attempts
"""

import asyncio
from aiohttp import web
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib

from app.honeypots.base import BaseHoneypot, HoneypotType
from app.core.config import settings

logger = logging.getLogger(__name__)

class URLTrapHoneypot(BaseHoneypot):
    def __init__(self, port: int = None, config: Dict[str, Any] = None):
        default_config = {
            "banner": "nginx/1.18.0 (Ubuntu)",
            "log_level": "INFO",
            "max_connections": 500,
            "trap_urls": [
                "/login.php", "/admin.php", "/wp-login.php",
                "/api/v1/auth", "/.git/config", "/backup.zip"
            ],
            "redirect_urls": [
                "/redirect", "/go", "/link", "/url"
            ],
            "tracking_params": ["utm_source", "ref", "token", "session"]
        }
        
        final_config = {**default_config, **(config or {})}
        final_port = port or settings.web_honeypot_port + 100
        
        super().__init__(HoneypotType.URL_TRAP, final_port, final_config)
        
        self.app = None
        self.runner = None
        self.site = None
        self.trap_hits = {}

    async def start(self):
        if self.is_running:
            logger.warning("URL trap honeypot already running")
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
            
            logger.info(f"URL trap honeypot started on port {self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start URL trap honeypot: {e}")
            self.is_running = False

    async def stop(self):
        if not self.is_running:
            return

        self.is_running = False
        
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
            
        logger.info("URL trap honeypot stopped")

    async def handle_connection(self, client_info: Dict[str, Any]):
        pass

    def _setup_routes(self):
        self.app.router.add_route('*', '/', self._handle_root)
        
        for trap_url in self.config["trap_urls"]:
            self.app.router.add_route('*', trap_url, self._handle_trap_url)
            
        for redirect_url in self.config["redirect_urls"]:
            self.app.router.add_route('*', redirect_url, self._handle_redirect_url)
            
        self.app.router.add_route('*', '/{path:.*}', self._handle_catch_all)

    async def _handle_root(self, request):
        return await self._process_url_trap(request, "root")

    async def _handle_trap_url(self, request):
        return await self._process_url_trap(request, "trap_url")

    async def _handle_redirect_url(self, request):
        return await self._process_url_trap(request, "redirect_url")

    async def _handle_catch_all(self, request):
        return await self._process_url_trap(request, "catch_all")

    async def _process_url_trap(self, request, url_type: str):
        client_ip = request.remote
        method = request.method
        path = request.path
        user_agent = request.headers.get('User-Agent', '')
        referer = request.headers.get('Referer', '')
        
        query_params = dict(request.query)
        tracking_data = self._extract_tracking_data(query_params)
        
        trap_id = self._generate_trap_id(path, query_params)
        self._record_trap_hit(trap_id, client_ip)
        
        event_data = {
            "source_ip": client_ip,
            "destination_port": self.port,
            "method": method,
            "url": path,
            "user_agent": user_agent,
            "referer": referer,
            "query_params": query_params,
            "tracking_data": tracking_data,
            "url_type": url_type,
            "trap_id": trap_id,
            "is_malicious": self._is_malicious_url(path, query_params, user_agent),
            "tags": self._generate_url_tags(path, query_params, user_agent, url_type)
        }
        
        await self.log_event(event_data)
        
        if url_type == "redirect_url" and "url" in query_params:
            return web.Response(
                status=302,
                headers={'Location': query_params['url']}
            )
        
        response_html = self._generate_trap_response(path, url_type)
        return web.Response(
            text=response_html,
            content_type='text/html',
            status=200
        )

    def _extract_tracking_data(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        tracking_data = {}
        
        for param in self.config["tracking_params"]:
            if param in query_params:
                tracking_data[param] = query_params[param]
                
        return tracking_data

    def _generate_trap_id(self, path: str, query_params: Dict[str, Any]) -> str:
        unique_string = f"{path}:{sorted(query_params.items())}"
        return hashlib.md5(unique_string.encode()).hexdigest()[:8]

    def _record_trap_hit(self, trap_id: str, client_ip: str):
        if trap_id not in self.trap_hits:
            self.trap_hits[trap_id] = {
                "hits": 0,
                "first_hit": datetime.utcnow(),
                "last_hit": datetime.utcnow(),
                "unique_ips": set()
            }
        
        self.trap_hits[trap_id]["hits"] += 1
        self.trap_hits[trap_id]["last_hit"] = datetime.utcnow()
        self.trap_hits[trap_id]["unique_ips"].add(client_ip)

    def _is_malicious_url(self, path: str, query_params: Dict[str, Any], user_agent: str) -> bool:
        malicious_indicators = [
            "cmd" in query_params,
            "exec" in query_params,
            "system" in query_params,
            "union" in str(query_params).lower(),
            "select" in str(query_params).lower(),
            "../" in path,
            any(tool in user_agent.lower() for tool in ["sqlmap", "nikto", "burp"])
        ]
        
        return any(malicious_indicators)

    def _generate_url_tags(self, path: str, query_params: Dict[str, Any], user_agent: str, url_type: str) -> List[str]:
        tags = [f"url_trap_{url_type}"]
        
        if any(param in query_params for param in self.config["tracking_params"]):
            tags.append("tracking_parameters")
            
        if any(x in path for x in [".php", ".asp", ".jsp"]):
            tags.append("dynamic_url")
            
        if self._is_malicious_url(path, query_params, user_agent):
            tags.append("malicious_url_access")
            
        return tags

    def _generate_trap_response(self, path: str, url_type: str) -> str:
        if url_type == "trap_url":
            return f"""
            <html>
            <head><title>Login Required</title></head>
            <body>
                <h1>Authentication Required</h1>
                <p>Please login to access this resource: {path}</p>
                <form method="post">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <button type="submit">Login</button>
                </form>
            </body>
            </html>
            """
        else:
            return f"""
            <html>
            <head><title>Page Not Found</title></head>
            <body>
                <h1>404 Not Found</h1>
                <p>The requested URL {path} was not found on this server.</p>
            </body>
            </html>
            """

    def get_detailed_stats(self) -> Dict[str, Any]:
        base_stats = self.get_stats()
        base_stats.update({
            "trap_urls": self.config["trap_urls"],
            "redirect_urls": self.config["redirect_urls"],
            "unique_traps_hit": len(self.trap_hits),
            "total_trap_hits": sum(hit["hits"] for hit in self.trap_hits.values()),
            "tracking_params": self.config["tracking_params"]
        })
        return base_stats