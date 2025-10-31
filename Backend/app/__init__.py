"""
Honeypot Cyber Threat Detection & Response System
Backend Application Package
"""

__version__ = "1.0.0"
__author__ = "Honeypot CTDR Team"
__description__ = "AI-Powered Honeypot Threat Detection System"

from app.core.config import settings
from app.core.database import init_db
from app.core.security import setup_security

def create_application():
    """Initialize core application components"""
    init_db()
    setup_security()
    
    from app.main import app
    return app

app = create_application()

__all__ = [
    "app",
    "settings",
    "create_application"
]